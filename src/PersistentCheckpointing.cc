#include "AutoRemoteSyscalls.h"
#include "BpfMapMonitor.h"
#include "CheckpointInfo.h"
#include "EmuFs.h"
#include "FileMonitor.h"
#include "MagicSaveDataMonitor.h"
#include "MmappedFileMonitor.h"
#include "NonvirtualPerfCounterMonitor.h"
#include "ODirectFileMonitor.h"
#include "PersistentCheckpointing.h"
#include "PreserveFileMonitor.h"
#include "ProcFdDirMonitor.h"
#include "ProcMemMonitor.h"
#include "ProcStatMonitor.h"
#include "RRPageMonitor.h"
#include "ReplayTask.h"
#include "ScopedFd.h"
#include "Session.h"
#include "StdioMonitor.h"
#include "SysCpuMonitor.h"
#include "Task.h"
#include "TaskishUid.h"
#include "TraceFrame.h"
#include "TraceStream.h"
#include "VirtualPerfCounterMonitor.h"
#include "log.h"
#include "replay_syscall.h"
#include "rr_pcp.capnp.h"
#include "stream_util.h"
#include "util.h"
#include <algorithm>
#include <sys/mman.h>
#include <sys/prctl.h>
namespace rr {

std::string checkpoints_index_file(const std::string& trace_dir) { return trace_dir + "/checkpoints"; }

void write_monitor(rr::trace::FileMonitor::Builder& builder, int fd, FileMonitor* monitor) {
  builder.setFd(fd);
  int t = monitor->type();
  builder.setType(t);
  switch (monitor->type()) {
    case FileMonitor::Mmapped: {
      auto contents = ((MmappedFileMonitor*)monitor)->info();
      auto mmap = builder.initMmap();
      LOG(debug) << "MMapped Monitor dead: " << std::get<0>(contents)
                 << " device: " << std::get<1>(contents)
                 << " inode: " << std::get<2>(contents);
      mmap.setDead(std::get<0>(contents));
      mmap.setDevice(std::get<1>(contents));
      mmap.setInode(std::get<2>(contents));
    } break;
    case FileMonitor::ProcFd: {
      auto pfd = builder.initProcFd();
      auto tuid = ((ProcFdDirMonitor*)monitor)->task_uuid();
      pfd.setPid(tuid.tid());
      pfd.setSerial(tuid.serial());
    } break;
    case FileMonitor::ProcMem: {
      auto pm = builder.initProcMem();
      auto auid = ((ProcMemMonitor*)monitor)->get_auid();
      pm.setExecCount(auid.exec_count());
      pm.setPid(auid.tid());
      pm.setSerial(auid.serial());
    } break;
    case FileMonitor::Stdio:
      builder.setStdio(((StdioMonitor*)monitor)->orig_fd());
      break;
    case FileMonitor::ProcStat:
      builder.setProcStat(str_to_data(((ProcStatMonitor*)monitor)->get_data()));
      break;
    case FileMonitor::BpfMap: {
      auto bpf = builder.initBpf();
      bpf.setKeySize(((BpfMapMonitor*)monitor)->key_size());
      bpf.setValueSize(((BpfMapMonitor*)monitor)->key_size());
    } break;
    default:
      break;
  }
}

bool should_serialize(const AddressSpace::Mapping& mapping) {
  return !mapping.map.is_vsyscall() &&
         !mapping.map.contains(AddressSpace::rr_page_start()) &&
         !mapping.map.contains(AddressSpace::preload_thread_locals_start());
}

static std::string file_name_of(const std::string& path) {
  auto pos = path.rfind("/");
  // means we're an "ok" filename (ok, means we have no path components - we're
  // either empty or just a file name)
  if (pos == std::string::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

// Passed from write_vm to each write_map call
class WriteVmConfig {
public:
  WriteVmConfig(Task* clone_leader, const char* data_dir, size_t buffer_size)
      : clone_leader(clone_leader), cp_data_dir(data_dir) {
    const auto procfs_mem = clone_leader->proc_mem_path();
    const auto procfs_pagemap = clone_leader->proc_pagemap_path();
    proc_mem_fd = ScopedFd{ procfs_mem.c_str(), O_RDONLY };
    proc_pagemap_fd = ScopedFd{ procfs_pagemap.c_str(), O_RDONLY };
    ASSERT(clone_leader, proc_mem_fd.is_open())
        << "Serializing VM for " << clone_leader->rec_tid
        << " failed. Couldn't open " << procfs_mem;
    ASSERT(clone_leader, proc_pagemap_fd.is_open())
        << "Serializing VM for " << clone_leader->rec_tid
        << " failed. Couldn't open " << procfs_mem;
    buffer = { .ptr = ::mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
               .size = buffer_size };
    if (buffer.ptr == MAP_FAILED)
      FATAL() << "Failed to create segment serializer buffer with capacity " << buffer_size;
  }

  ~WriteVmConfig() { ::munmap(buffer.ptr, buffer.size); }

  Task* clone_leader;
  ScopedFd proc_mem_fd;
  ScopedFd proc_pagemap_fd;
  const char* cp_data_dir;

  struct {
    void* ptr;
    size_t size;
  } buffer;
};

#define PAGE_PRESENT(page_map_entry) page_map_entry & (1ul << 63)
#define PAGE_SWAPPED(page_map_entry) page_map_entry & (1ul << 62)
#define PAGE_FILE_OR_SHARED_ANON(page_map_entry) page_map_entry & (1ul << 61)
#define FILE_OP_FATAL(file) FATAL() << "write_map failed for " << std::string{ file } << " "
constexpr auto PRIVATE_ANON = MAP_ANONYMOUS | MAP_PRIVATE;



static void write_map(const WriteVmConfig& cfg, rr::trace::KernelMapping::Builder builder, const AddressSpace::Mapping& map) {
  builder.setStart(map.map.start().as_int());
  builder.setEnd(map.map.end().as_int());
  builder.setFsname(str_to_data(map.recorded_map.fsname()));
  builder.setDevice(map.map.device());
  builder.setInode(map.recorded_map.inode());
  builder.setProtection(map.map.prot());
  builder.setFlags(map.map.flags());
  // This will be interpreted as 0 on restore, since we create files for
  // individual mappings.
  builder.setOffset(map.map.file_offset_bytes());

  std::vector<uint64_t> pagemap_entries{};
  const auto page_count = map.map.page_count();
  pagemap_entries.resize(page_count);

  const auto read_idx_start = (map.map.start().as_int() / page_size()) * 8;
  DEBUG_ASSERT(read_idx_start % 8 == 0);

  // walk the page map entries for mapping and determine on how we represent (or not represent) it's data in the capnproto file
  auto entries_read_sz = ::pread(cfg.proc_pagemap_fd, pagemap_entries.data(), page_count * sizeof(uint64_t), read_idx_start);
  if(entries_read_sz == -1) FATAL() << "Failed to read page map";
  auto pages_present = 0;
  bool all_not_file_or_shared = true;
  for(auto pme : pagemap_entries) {
    if (PAGE_PRESENT(pme)) pages_present++;
    // probably don't have to check _all_ of the mappings for this, since we know the entire segment up front.
    if (PAGE_FILE_OR_SHARED_ANON(pme)) all_not_file_or_shared = false;
  }

  // "guard segment": untouched, uninitialized memory, we don't write it's contents
  if ((map.map.flags() & PRIVATE_ANON) == PRIVATE_ANON && pages_present == 0 && map.map.prot() == PROT_NONE && all_not_file_or_shared) {
    builder.initMapType().setGuardSegment();
  } else {
    auto map_type = builder.initMapType();

    const auto pid = cfg.clone_leader->tid;
    const auto fname = file_name_of(map.map.fsname());
    // XXX when/if RR moves to c++20, use std::format.
    const auto len = std::snprintf(
        nullptr, 0, "%s/%d-%s-%p-%p", cfg.cp_data_dir, pid, fname.c_str(),
        (void*)map.map.start().as_int(), (void*)map.map.end().as_int());
    char file[len + 1];
    if (map.map.fsname().empty()) {
      std::snprintf(file, len, "%s/%d-%p-%p", cfg.cp_data_dir, pid,
                    (void*)map.map.start().as_int(),
                    (void*)map.map.end().as_int());
    } else {
      std::snprintf(file, len, "%s/%d-%s-%p-%p", cfg.cp_data_dir, pid,
                    fname.c_str(), (void*)map.map.start().as_int(),
                    (void*)map.map.end().as_int());
    }
    ScopedFd f{ file, O_EXCL | O_CREAT | O_RDWR, 0777 };
    if (!f.is_open()) FILE_OP_FATAL(file) << "Couldn't open file";

    const auto sz = ::ftruncate(f, map.map.size());
    if (sz == -1) FILE_OP_FATAL(file) << "couldn't truncate file to size " << map.map.size();

    const auto bytes_read = ::pread(cfg.proc_mem_fd, cfg.buffer.ptr, map.map.size(), map.map.start().as_int());
    if (bytes_read == -1) FILE_OP_FATAL(file) << " couldn't read contents of " << map.map.str();

    ASSERT(cfg.clone_leader,
           static_cast<unsigned long>(bytes_read) == map.map.size())
        << " data read from /proc/" << cfg.clone_leader->tid
        << "/mem did not match kernel mapping metadata"
        << " read " << bytes_read << " expected: " << map.map.size() << " of "
        << map.map.str();

    const auto written_bytes = ::write(f, cfg.buffer.ptr, map.map.size());
    if (written_bytes == -1) FILE_OP_FATAL(file) << " couldn't write contents of " << map.map.str();

    const std::string data_fname{file};
    const auto contents_path = str_to_data(data_fname);
    if(map.emu_file) {
      auto shared_anon = map_type.initSharedAnon();
      const auto isSysVSegment = cfg.clone_leader->vm()->has_shm_at(map.map) || cfg.clone_leader->vm()->has_shm_at(map.recorded_map);
      shared_anon.setSkipMonitoringMappedFd(map.monitored_shared_memory == nullptr);
      shared_anon.setContentsPath(contents_path);
      shared_anon.setIsSysVSegment(isSysVSegment);
    } else {
      if(map.map.fsname().empty() || map.map.is_stack() || map.map.is_heap()) {
        map_type.initPrivateAnon().setContentsPath(contents_path);
      } else {
        map_type.initFile().setContentsPath(contents_path);
      }
    }
  }
}

void write_vm(Task* clone_leader, rr::trace::CloneLeader::Builder builder, const std::string& checkpoint_data_dir) {
  if (::mkdir(checkpoint_data_dir.c_str(), 0700) != 0) {
    LOG(info) << " directory " << checkpoint_data_dir << " already exists.";
  }

  std::vector<const AddressSpace::Mapping*> mappings;
  auto copy_buffer_size = 0ul;
  // any stack mapping will do. It has to be mapped first, mimicking `process_execve` at restore
  const AddressSpace::Mapping* stack_mapping = nullptr;
  for (const auto& m : clone_leader->vm()->maps()) {
    if (should_serialize(m)) {
      if(m.recorded_map.is_stack() && stack_mapping == nullptr) {
        stack_mapping = &m;
      } else {
        mappings.push_back(&m);
      }
      // largest mapping in the vm; use that as buffer size
      copy_buffer_size = std::max(copy_buffer_size, m.map.size());
    }
  }

  ASSERT(clone_leader, !mappings.empty()) << "No mappings found to serialize";
  copy_buffer_size = ceil_page_size(copy_buffer_size);
  WriteVmConfig cfg{clone_leader, checkpoint_data_dir.c_str(), copy_buffer_size};

  auto kernel_mappings = builder.initVirtualAddressSpace(mappings.size()+1);
  auto idx = 0;
  // write the/a stack mapping first. We're mimicking process_execve, therefore we need a stack segment first
  write_map(cfg, kernel_mappings[idx++], *stack_mapping);
  for (auto m : mappings) {
    write_map(cfg, kernel_mappings[idx++], *m);
  }
}

void map_region_file(AutoRemoteSyscalls& remote, const KernelMapping& km, const std::string& file_path) {
  struct stat real_file;
  std::string real_file_name;
  LOG(debug) << "directly mmap'ing " << km.size() << " bytes of "
             << file_path << " at offset "
             << HEX(km.file_offset_bytes()) << "(" << km.str() << ")";
  remote.finish_direct_mmap(km.start(), km.size(), km.prot(),
                            ((km.flags() & ~MAP_GROWSDOWN) | MAP_PRIVATE),
                            file_path.c_str(), O_RDONLY, 0, real_file,
                            real_file_name);
  remote.task()->vm()->map(remote.task(), km.start(), km.size(), km.prot(), km.flags(), km.file_offset_bytes(), km.fsname(), km.device(), km.inode(), nullptr, &km);
}

void map_private_anonymous(AutoRemoteSyscalls& remote, const KernelMapping& km) {
  LOG(debug) << "map region no file: " << km.str();
  remote.infallible_mmap_syscall_if_alive(
      km.start(), km.size(), km.prot(),
      (km.flags() & ~MAP_GROWSDOWN) | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  remote.task()->vm()->map(remote.task(), km.start(), km.size(), km.prot(),
                           km.flags(), km.file_offset_bytes(), km.fsname(),
                           km.device(), km.inode(), nullptr, &km);
}

Task::CapturedState reconstitute_captured_state(ReplaySession& s, trace::CapturedState::Reader reader) {
  Task::CapturedState res;
  res.ticks = reader.getTicks();
  {
    auto register_raw = reader.getRegs().getRaw();
    res.regs = Registers{ s.arch() };
    res.regs.set_from_trace(s.arch(), register_raw.begin(),
                            register_raw.size());
  }
  {
    auto raw = reader.getExtraRegs().getRaw();
    set_extra_regs_from_raw(s.arch(), s.trace_reader().cpuid_records(), raw, res.extra_regs);
  }

  res.prname = data_to_str(reader.getPrname());
  res.fdtable_identity = reader.getFdtableIdentity();
  res.syscallbuf_child = reader.getSyscallbufChild();
  res.syscallbuf_size = reader.getSyscallbufSize();
  res.num_syscallbuf_bytes = reader.getNumSyscallbufBytes();
  res.preload_globals = reader.getPreloadGlobals();
  res.scratch_ptr = reader.getScratchPtr();
  res.scratch_size = reader.getScratchSize();
  res.top_of_stack = reader.getTopOfStack();
  {
    auto rs = reader.getRseqState();
    res.rseq_state = std::make_unique<RseqState>(remote_ptr<void>(rs.getPtr()),
                                                 rs.getAbortPrefixSignature());
  }
  res.cloned_file_data_offset = reader.getClonedFileDataOffset();
  {
    memcpy(res.thread_locals, reader.getThreadLocals().asBytes().begin(),
           PRELOAD_THREAD_LOCALS_SIZE);
  }

  res.rec_tid = reader.getRecTid();
  res.own_namespace_rec_tid = reader.getOwnNamespaceRecTid();
  res.serial = reader.getSerial();
  res.tguid = ThreadGroupUid{ reader.getTguid().getTid(),
                              reader.getTguid().getSerial() };
  res.desched_fd_child = reader.getDeschedFdChild();
  res.cloned_file_data_fd_child = reader.getClonedFileDataFdChild();
  res.cloned_file_data_fname = data_to_str(reader.getClonedFileDataFname());
  res.wait_status = WaitStatus{ reader.getWaitStatus() };
  res.tls_register = reader.getTlsRegister();

  res.thread_areas = {};
  for (const auto& ta : reader.getThreadAreas()) {
    const X86Arch::user_desc item = *(X86Arch::user_desc*)ta.begin();
    res.thread_areas.push_back(item);
  }

  return res;
}

void init_scratch_memory(ReplayTask* t, const KernelMapping& km) {

  t->scratch_ptr = km.start();
  t->scratch_size = km.size();
  size_t sz = t->scratch_size;

  ASSERT(t, (km.prot() & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE));
  ASSERT(t, (km.flags() & (MAP_PRIVATE | MAP_ANONYMOUS)) ==
                (MAP_PRIVATE | MAP_ANONYMOUS));

  {
    AutoRemoteSyscalls remote(t);
    remote.infallible_mmap_syscall_if_alive(t->scratch_ptr, sz, km.prot(),
                                            km.flags() | MAP_FIXED, -1, 0);
    t->vm()->map(t, t->scratch_ptr, sz, km.prot(), km.flags(), 0, std::string(),
                 KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                 &km);
  }
  t->setup_preload_thread_locals();
}

void write_capture_state(trace::CapturedState::Builder& ms, const Task::CapturedState& state) {
  ms.setTicks(state.ticks);
  ms.initRegs().setRaw(regs_to_raw(state.regs));
  ms.initExtraRegs().setRaw(extra_regs_to_raw(state.extra_regs));
  ms.setPrname(str_to_data(state.prname));
  ms.setFdtableIdentity(state.fdtable_identity);
  ms.setSyscallbufChild(state.syscallbuf_child.as_int());
  ms.setSyscallbufSize(state.syscallbuf_size);
  ms.setNumSyscallbufBytes(state.num_syscallbuf_bytes);
  ms.setPreloadGlobals(state.preload_globals.as_int());
  ms.setScratchPtr(state.scratch_ptr.as_int());
  ms.setScratchSize(state.scratch_size);
  ms.setTopOfStack(state.top_of_stack.as_int());
  auto rseq = ms.initRseqState();
  if (state.rseq_state) {
    rseq.setPtr(state.rseq_state->ptr.as_int());
    rseq.setAbortPrefixSignature(state.rseq_state->abort_prefix_signature);
  } else {
    rseq.setPtr(0);
    rseq.setAbortPrefixSignature(0);
  }

  ms.setClonedFileDataOffset(state.cloned_file_data_offset);
  ms.setThreadLocals(
      { (Byte*)state.thread_locals, sizeof(state.thread_locals) });
  ms.setRecTid(state.rec_tid);
  ms.setOwnNamespaceRecTid(state.own_namespace_rec_tid);
  ms.setSerial(state.serial);
  auto tguid = ms.initTguid();
  tguid.setTid(state.tguid.tid());
  tguid.setSerial(state.tguid.serial());
  ms.setDeschedFdChild(state.desched_fd_child);
  ms.setClonedFileDataFdChild(state.cloned_file_data_fd_child);
  ms.setClonedFileDataFname(str_to_data(state.cloned_file_data_fname));
  ms.setWaitStatus(state.wait_status.get());
  ms.setTlsRegister(state.tls_register);
  auto thread_areas = ms.initThreadAreas(state.thread_areas.size());
  auto i = 0;
  for (const auto& ta : state.thread_areas) {
    thread_areas[i++] = capnp::Data::Builder{ (Byte*)&ta, sizeof(ta) };
  }
}

void update_serialized_checkpoints(
    const std::string& trace_dir,
    SupportedArch arch,
    const std::vector<CPUIDRecord>& cpuid_recs,
    const std::vector<CheckpointInfo>& checkpoints) {

  auto checkpoints_file = trace_dir + "/checkpoints";
  auto cps = get_checkpoint_infos(trace_dir, arch, cpuid_recs);

  // remove checkpoints on disk, which are not represented in |checkpoints|
  for (auto& cp : cps) {
    if (std::find_if(checkpoints.cbegin(), checkpoints.cend(), [&](auto& cp_) {
          return cp == cp_;
        }) == std::cend(checkpoints)) {
      cp.delete_from_disk();
    }
  }

  // remove old file
  remove(checkpoints_file.c_str());

  if (checkpoints.empty())
    return;

  // and write a new one
  auto fd = ScopedFd(checkpoints_file.c_str(), O_EXCL | O_CREAT | O_RDWR, 0700);
  if (!fd.is_open())
    FATAL() << "failed to open file " << checkpoints_file;

  capnp::MallocMessageBuilder message;
  auto cc = message.initRoot<trace::PersistentCheckpoints>();
  auto list = cc.initCheckpoints(checkpoints.size());
  auto idx = 0;
  for (const auto& cp : checkpoints) {
    auto entry = list[idx++];
    entry.setCloneCompletionFile(str_to_data(cp.info_file));
    entry.setTime(cp.time);
    entry.setId(cp.unique_id);

    auto tuid = entry.initLastContinueTuid();
    tuid.setPid(cp.last_continue_tuid.tid());
    tuid.setSerial(cp.last_continue_tuid.serial());
    entry.setWhere(str_to_data(cp.where));

    entry.setStepKey(cp.step_key);
    entry.setTicks(cp.ticks);;
    entry.initRegs().setRaw(regs_to_raw(cp.regs));
    auto ras = entry.initReturnAddresses(8);
    for (auto i = 0; i < 8; i++) {
      ras.set(i, cp.return_addresses.addresses[i].as_int());
    }

    entry.initExtraRegs().setRaw(extra_regs_to_raw(cp.extra_regs));
    entry.setTicksAtEventStart(cp.ticks_at_event_start);
    entry.setSinglestepToNextMarkNoSignal(cp.singlestep_to_next_mark_no_signal);
  }
  capnp::writePackedMessageToFd(fd, message);
}



} // namespace rr