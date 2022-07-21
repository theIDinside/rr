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
#include "WaitStatus.h"
#include "log.h"
#include "replay_syscall.h"
#include "rr_pcp.capnp.h"
#include "stream_util.h"
#include "util.h"
#include <algorithm>
#include <asm-generic/mman-common.h>
#include <bits/types/siginfo_t.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
namespace rr {

// For re-factor simplicity.
std::string checkpoints_index_file(const std::string& trace_dir) { return trace_dir + "/checkpoints"; }

DeserializedMapping::DeserializedMapping(const KernelMapping& km,
                                         std::string map_contents_filename,
                                         bool has_emu, bool is_sysv_segment)
    : km(km),
      has_emu_file(has_emu),
      is_sysv_segment(is_sysv_segment),
      map_contents_file(std::move(map_contents_filename)),
      name(this->km.fsname().c_str()) {}

std::vector<Byte> DeserializedMapping::read_map_data() {
  std::vector<Byte> data;
  data.resize(km.size());
  const auto fd = ScopedFd{ map_file_path(), O_RDONLY };
  if (fd < 0)
    FATAL() << "failed to open " << map_contents_file;
  const auto sz = ::read(fd, data.data(), km.size());
  if (sz < 0) {
    FATAL() << " failed to read " << map_contents_file << " for " << km.str();
  }
  read_data_size = static_cast<size_t>(sz);
  return data;
}

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

// we take ownership of |data| because it's meant to be immediately discarded in
// the RR supervisor.
void write_shared_memory_map(ReplayTask* new_task, const KernelMapping& km, std::vector<Byte>&& data) {
  bool write_ok = true;
  auto bytes_written = new_task->write_bytes_helper_no_notifications(
      km.start(), km.size(), data.data(), &write_ok);
  ASSERT(new_task, write_ok)
      << "Failed to write deserialized contents to memory map " << km.str();
  ASSERT(new_task, static_cast<size_t>(bytes_written) == km.size())
      << "Failed to deserialize contents into mapping. Wrote " << bytes_written
      << "; expected " << km.size();
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

struct WriteVmConfig {
  Task* clone_leader;
  ScopedFd& proc_mem_fd;
  const char* cp_data_dir;
  // Buffer to read data from /proc/tid/mem into. Must be able to hold largest map in VM
  struct {
    void* ptr;
    size_t size;
  } buffer;
};


#define FILE_OP_FATAL(file) FATAL() << "write_map failed for " << std::string{ file } << " "
void write_map(WriteVmConfig cfg, rr::trace::KernelMapping::Builder builder, const AddressSpace::Mapping& map) {
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
  builder.setHasEmuFile(map.emu_file != nullptr);

  const auto res = lseek(cfg.proc_mem_fd, map.map.start().as_int(), SEEK_SET);
  if (res == -1)
    FATAL() << "(lseek failed) write_map failed for " << map.map.str();
  // /XXX c++20 _really_ would be useful for a lot of this stuff (std::format is
  // actually faster (and safer) than snprintf)
  const auto pid = cfg.clone_leader->tid;
  const auto len =
      std::snprintf(nullptr, 0, "%s/%d-%s-%p-%p", cfg.cp_data_dir, pid,
                    file_name_of(map.map.fsname()).c_str(), (void*)map.map.start().as_int(), (void*)map.map.end().as_int());
  char file[len + 1];
  if (map.map.fsname().empty()) {
    std::snprintf(file, len, "%s/%d-%p-%p", cfg.cp_data_dir, pid,
                  (void*)map.map.start().as_int(), (void*)map.map.end().as_int());
  } else {
    std::snprintf(file, len, "%s/%d-%s-%p-%p", cfg.cp_data_dir, pid,
                  file_name_of(map.map.fsname()).c_str(), (void*)map.map.start().as_int(),
                  (void*)map.map.end().as_int());
  }

  ScopedFd f{ file, O_EXCL | O_CREAT | O_RDWR, 0700 };

  if (!f.is_open())
    FILE_OP_FATAL(file) << "Couldn't open file";

  const auto sz = ::ftruncate(f, map.map.size());
  if (sz == -1)
    FILE_OP_FATAL(file) << "couldn't truncate file to size " << map.map.size();

  const auto bytes_read = ::read(cfg.proc_mem_fd, cfg.buffer.ptr, map.map.size());
  if (bytes_read == -1)
    FILE_OP_FATAL(file) << " couldn't read contents of " << map.map.str();

  ASSERT(cfg.clone_leader, static_cast<unsigned long>(bytes_read) == map.map.size())
      << " data read from /proc/" << cfg.clone_leader->tid
      << "/mem did not match kernel mapping metadata"
      << " read " << bytes_read << " expected: " << map.map.size() << " of " << map.map.str().c_str();

  const auto written_bytes = ::write(f, cfg.buffer.ptr, map.map.size());
  if (written_bytes == -1)
    FILE_OP_FATAL(file) << " couldn't write contents of " << map.map.str();

  builder.setContentsPath(str_to_data(file));
  builder.setRrSysMap(0);
  const auto isSysVSegment = cfg.clone_leader->vm()->has_shm_at(map.map) || cfg.clone_leader->vm()->has_shm_at(map.recorded_map);
  builder.setIsSysVSegment(isSysVSegment);
}

void write_vm(Task* clone_leader, rr::trace::CloneLeader::Builder builder, const std::string& checkpoint_data_dir) {
  const auto procfs_mem = clone_leader->proc_mem_path();
  auto proc_mem_fd = ScopedFd{ procfs_mem.c_str(), O_RDONLY };
  std::vector<const AddressSpace::Mapping*> mappings;
  if (!proc_mem_fd.is_open()) {
    FATAL() << "Serializing VMA for " << clone_leader->rec_tid
            << " failed. Couldn't open " << procfs_mem;
  }

  if (::mkdir(checkpoint_data_dir.c_str(), 0700) != 0) {
    LOG(info) << " directory " << checkpoint_data_dir << " already exists.";
  }

  auto copy_buffer_size = 0ul;
  for (const auto& m : clone_leader->vm()->maps()) {
    if (should_serialize(m)) {
      mappings.push_back(&m);
      copy_buffer_size = std::max(copy_buffer_size, m.map.size());
    }
  }
  ASSERT(clone_leader, !mappings.empty()) << "No mappings found to serialize";
  copy_buffer_size = ceil_page_size(copy_buffer_size);

  WriteVmConfig cfg{
    .clone_leader = clone_leader,
    .proc_mem_fd = proc_mem_fd,
    .cp_data_dir = checkpoint_data_dir.c_str(),
    .buffer = { .ptr = ::mmap(nullptr, copy_buffer_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
                .size = copy_buffer_size }
  };

  if (cfg.buffer.ptr == MAP_FAILED)
    FATAL() << "Failed to create segment serializer buffer with capacity "
            << copy_buffer_size;

  // we should already know up front what maps we don't serialize, but for now,
  // I'm doing this
  auto kernel_mappings = builder.initVirtualAddressSpace(mappings.size());
  auto idx = 0;
  for (auto m : mappings) {
    write_map(cfg, kernel_mappings[idx++], *m);
  }
  ::munmap(cfg.buffer.ptr, cfg.buffer.size);
}

// N.B! Slow.
void verify_map_contains_same_as_serialized(ReplayTask* task,
                                         const DeserializedMapping& buf_map,
                                         const std::vector<Byte>& data,
                                         const char* map_name) {
  unsigned char buf[buf_map.km.size()];
  task->read_bytes_fallible(buf_map.km.start(), buf_map.km.size(), buf);
  auto i = 0;
  for (auto b : buf) {
    ASSERT(task, b == *(data.data() + i))
        << "Contents of " << map_name
        << " mapped in task does not match serialized data at offset " << i
        << " => (memory/serialized)" << (uint64_t)b << "/"
        << (uint64_t) * (data.data() + i);
    i++;
  }
}


void map_region_file(AutoRemoteSyscalls& remote, const DeserializedMapping& metadata) {
  struct stat real_file;
  std::string real_file_name;
  const auto& km = metadata.km;
  LOG(debug) << "directly mmap'ing " << km.size() << " bytes of "
             << metadata.map_file_path() << " at offset "
             << HEX(metadata.km.file_offset_bytes());
  remote.finish_direct_mmap(km.start(), km.size(), km.prot(),
                            ((km.flags() & ~MAP_GROWSDOWN) | MAP_PRIVATE),
                            metadata.map_file_path(), O_RDWR, 0, real_file,
                            real_file_name);
  remote.task()->vm()->map(remote.task(), metadata.km.start(), km.size(),
                           km.prot(), km.flags(), km.file_offset_bytes(),
                           km.fsname(), km.device(), km.inode(), nullptr, &km);
}

void map_region_no_file(AutoRemoteSyscalls& remote, const KernelMapping& km) {
  // printf("map_region_no_file for km: %s (%lu KB)\n", km.str().c_str(),
  // km.size() / 1024);
  remote.infallible_mmap_syscall_if_alive(km.start(), km.size(), km.prot(),
                                          (km.flags() & ~MAP_GROWSDOWN) |
                                              MAP_FIXED | MAP_ANONYMOUS,
                                          -1, km.file_offset_bytes());
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
    X86Arch::user_desc item = *(X86Arch::user_desc*)ta.begin();
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

static bool is_auto_mapped(const KernelMapping& km) {
  return km.start() == AddressSpace::rr_page_start() ||
         km.start() == AddressSpace::preload_thread_locals_start() ||
         km.is_vsyscall();
}

static bool vdso_or_stack(const std::string& name) {
  return name.size() > 0 && name[0] == '[';
}

std::vector<DeserializedMapping> read_mappings(const trace::CloneLeader::Reader& reader, bool* executable_map_found) {
  auto mappings_data = reader.getVirtualAddressSpace();
  std::vector<DeserializedMapping> mappings{};
  mappings.reserve(mappings_data.size());
  for (const auto& km_data : mappings_data) {
    KernelMapping km(
        remote_ptr<void>(km_data.getStart()), km_data.getEnd(),
        km_data.hasFsname() ? km_data.getFsname().asChars().begin() : "",
        km_data.getDevice(), km_data.getInode(), km_data.getProtection(),
        km_data.getFlags(), km_data.getOffset());
    if (!is_auto_mapped(km) && km.size() != 0) {
      if (executable_map_found && km.is_executable() &&
          !vdso_or_stack(km.fsname())) {
        *executable_map_found = true;
      }
      mappings.push_back(DeserializedMapping{
          std::move(km), data_to_str(km_data.getContentsPath()),
          km_data.getHasEmuFile(), km_data.getIsSysVSegment() });
    }
  }
  return mappings;
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

inline const char* DeserializedMapping::map_file_path() const {
  return map_contents_file.c_str();
}

} // namespace rr