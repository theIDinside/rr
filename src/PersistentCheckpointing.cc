#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "EmuFs.h"
#include "ExtraRegisters.h"
#include "MagicSaveDataMonitor.h"
#include "MmappedFileMonitor.h"
#include "PersistentCheckpointing.h"
#include "PreserveFileMonitor.h"
#include "Registers.h"
#include "ReplayTask.h"
#include "ReturnAddressList.h"
#include "ScopedFd.h"
#include "SerializedCheckpoint.h"
#include "Session.h"
#include "StdioMonitor.h"
#include "Task.h"
#include "TraceFrame.h"
#include "TraceStream.h"
#include "WaitStatus.h"
#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "log.h"
#include "preload/preload_interface.h"
#include "replay_syscall.h"
#include "rr_pcp.capnp.h"
#include <algorithm>
#include <asm-generic/mman-common.h>
#include <capnp/blob.h>
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iterator>
#include <linux/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
namespace rr {

KernelMapWriter::KernelMapWriter(Task* task, std::string checkpoint_data_dir)
    : pid(task->tid), checkpoint_directory(std::move(checkpoint_data_dir)) {
  auto procfs_mem = "/proc/" + std::to_string(pid) + "/mem";
  proc_mem_fd = open(procfs_mem.c_str(), O_RDONLY);
  if (proc_mem_fd < 0) {
    FATAL() << "Failed to open " << procfs_mem;
  }
  if (mkdir(map_data_dir(), 0700) != 0)
    FATAL() << "Failed to create checkpoint data directory " << map_data_dir();
}

KernelMapWriter::~KernelMapWriter() { close(proc_mem_fd); }

DeserializedMapping::DeserializedMapping(const KernelMapping& km,
                                         std::string map_contents_filename,
                                         bool has_emu)
    : km(km), hasEmu(has_emu), data_{} {
  data_.resize(km.size());
  printf("Opening file for processing %s\n", map_contents_filename.c_str());
  fd = open(map_contents_filename.c_str(), O_RDONLY);

  if (fd < 0)
    FATAL() << "failed to open " << map_contents_filename;
  if(read(fd, data_.data(), km.size()) < 0) {
    FATAL() << " failed to read " << map_contents_filename << " for " << km.str();
  }
  close(fd);
}

std::string KernelMapWriter::file_name_of(const std::string& path) {
  auto pos = path.rfind("/");
  // means we're an "ok" filename (ok, means we have no path components - we're
  // either empty or just a file name)
  if (pos == std::string::npos) {
    return path;
  }
  return path.substr(pos);
}

std::string KernelMapWriter::write_map(const KernelMapping& km) const {
#define FILE_OP_FATAL(file)                                                    \
  FATAL() << "write_map failed for " << std::string{ file } << " "

  const auto res = lseek(proc_mem_fd, km.start().as_int(), SEEK_SET);
  if (res == -1)
    FATAL() << "(lseek failed) write_map failed for " << km.str();
  // /XXX c++20 _really_ would be useful for a lot of this stuff (std::format is
  // actually faster (and safer) than snprintf)
  const auto len =
      std::snprintf(nullptr, 0, "%s/%s-%p-%p", map_data_dir(),
                    file_name_of(km.fsname()).c_str(),
                    (void*)km.start().as_int(), (void*)km.end().as_int());
  char file[len + 1];
  if (km.fsname().empty()) {
    std::snprintf(file, len, "%s/%p-%p", map_data_dir(),
                  (void*)km.start().as_int(), (void*)km.end().as_int());
  } else {
    std::snprintf(file, len, "%s/%s-%p-%p", map_data_dir(),
                  file_name_of(km.fsname()).c_str(), (void*)km.start().as_int(),
                  (void*)km.end().as_int());
  }
  auto f = ScopedFd(file, O_WRONLY | O_APPEND | O_CREAT, 0700);

  if (!f)
    FILE_OP_FATAL(file) << "Couldn't open file";

  auto sz = ftruncate(f.get(), km.size());
  if (sz == -1)
    FILE_OP_FATAL(file) << "couldn't truncate file to size " << km.size();

  // crazy amount of copying. but right now, who cares.
  std::vector<Byte> data;
  data.reserve(km.size());
  auto bytes_read = read(proc_mem_fd, data.data(), km.size());
  if (bytes_read == -1)
    FILE_OP_FATAL(file) << "couldn't read contents of " << km.str();

  if (write(f.get(), data.data(), data.size()) == -1)
    FILE_OP_FATAL(file) << "couldn't write contents of " << km.str();

  return file;
}

void slow_verify_syscall_buffer_contents(ReplayTask* task,
                                         const DeserializedMapping& buf_map,
                                         const char* map_name) {
  printf("verifying %s [%s]: ", map_name, buf_map.km.str().c_str());
  unsigned char buf[buf_map.km.size()];
  task->read_bytes_fallible(buf_map.km.start(), buf_map.km.size(), buf);
  auto i = 0;
  for (auto b : buf) {
    ASSERT(task, b == *(buf_map.data(i)))
        << "Contents of " << map_name
        << " mapped in task does not match serialized data at offset " << i
        << " => (memory/serialized)" << (uint64_t)b << "/"
        << (uint64_t) * (buf_map.data(i));
    i++;
  }
  printf("Verification of %s contents OK! (verified %d bytes)\n", map_name, i);
}

// XXX move to trace_utils
const auto regs_to_raw = [](auto& regs) -> capnp::Data::Reader {
  return { regs.get_ptrace_for_self_arch().data,
           regs.get_ptrace_for_self_arch().size };
};

// XXX move to trace_utils
const auto extra_regs_to_raw = [](auto& extra_regs) -> capnp::Data::Reader {
  return { extra_regs.data().data(), extra_regs.data().size() };
};

// XXX move to trace_utils
const auto data_to_str = [](auto data) -> std::string {
  return std::string{ data.asChars().begin(), data.size() };
};

// XXX move to trace_utils
static kj::ArrayPtr<const capnp::byte> str_to_data(const std::string& str) {
  return kj::ArrayPtr<const capnp::byte>(
      reinterpret_cast<const capnp::byte*>(str.data()), str.size());
}

// XXX move to trace_utils
static trace::Arch to_trace_arch(SupportedArch arch) {
  switch (arch) {
    case x86:
      return trace::Arch::X86;
    case x86_64:
      return trace::Arch::X8664;
    case aarch64:
      return trace::Arch::AARCH64;
    default:
      FATAL() << "Unknown arch";
      return trace::Arch::X86;
  }
}

// utility functions for now. Will be removed.

std::unique_ptr<ScopedFd> create_new_exclusive(const char* path) {
  auto fd = std::make_unique<ScopedFd>(path, O_EXCL | O_CREAT | O_RDWR, 0700);
  if (!fd->is_open())
    FATAL() << "failed to open file " << path;
  return fd;
}

void map_region(ReplayTask* t, AutoRemoteSyscalls& remote,
                const KernelMapping& km, TraceReader::MappedDataSource source,
                const std::string& file_name) {
  std::string real_file_name;
  dev_t device = KernelMapping::NO_DEVICE;
  ino_t inode = KernelMapping::NO_INODE;
  int flags = km.flags();
  uint64_t offset_bytes = 0;
  switch (source) {
    case TraceReader::SOURCE_FILE: {
      struct stat real_file;
      offset_bytes = km.file_offset_bytes();
      printf("file offset for mapping %lu\n", offset_bytes);
      // Private mapping, so O_RDONLY is always OK.
      remote.finish_direct_mmap(km.start(), km.size(), km.prot(), km.flags(),
                                file_name, O_RDONLY, offset_bytes, real_file,
                                real_file_name);
      device = real_file.st_dev;
      inode = real_file.st_ino;
      break;
    }
    case TraceReader::SOURCE_TRACE:
    case TraceReader::SOURCE_ZERO:
      flags |= MAP_ANONYMOUS;
      remote.infallible_mmap_syscall_if_alive(
          km.start(), km.size(), km.prot(),
          (flags & ~MAP_GROWSDOWN) | MAP_FIXED, -1, 0);
      // The data, if any, will be written back by
      // ReplayTask::apply_all_data_records_from_trace
      break;
    default:
      ASSERT(t, false) << "Unknown data source";
      break;
  }

  t->vm()->map(t, km.start(), km.size(), km.prot(), flags, offset_bytes,
               real_file_name, device, inode, nullptr, &km);
}

void map_region_no_file(AutoRemoteSyscalls& remote, const KernelMapping& km) {
  // printf("map_region_no_file for km: %s (%lu KB)\n", km.str().c_str(),
  // km.size() / 1024);
  remote.infallible_mmap_syscall_if_alive(
      km.start(), km.size(), km.prot(),
      (km.flags() & ~MAP_GROWSDOWN) | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  remote.task()->vm()->map(remote.task(), km.start(), km.size(), km.prot(),
                           km.flags(), km.file_offset_bytes(), km.fsname(),
                           km.device(), km.inode(), nullptr, &km);
}

static ExtraRegisters get_extra_regs(ReplaySession& rs, ReplayTask* task,
                                     capnp::Data::Reader& extra_register_raw);

// Terrible. Just terrible. I know. But for now, it does what it is supposed to.
Task::CapturedState reconstitute(ReplaySession& s, ReplayTask* clone_leader,
                                 trace::CapturedState::Reader reader) {
  Task::CapturedState res;
  res.ticks = reader.getTicks();
  {
    auto register_raw = reader.getRegs().getRaw();
    res.regs = Registers{ s.arch() };
    res.regs.set_from_trace(s.arch(), register_raw.begin(),
                            register_raw.size());
  }
  {
    auto extra_register_raw = reader.getExtraRegs().getRaw();
    res.extra_regs = get_extra_regs(s, clone_leader, extra_register_raw);
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

static void init_scratch_memory(ReplayTask* t, const KernelMapping& km) {

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

static ExtraRegisters get_extra_regs(ReplaySession& rs, ReplayTask* task,
                                     capnp::Data::Reader& extra_register_raw) {
  if (extra_register_raw.size()) {
    ExtraRegisters::Format fmt;
    switch (rs.arch()) {
      default:
        FATAL() << "Unknown architecture";
        RR_FALLTHROUGH;
      case x86:
      case x86_64:
        fmt = ExtraRegisters::XSAVE;
        break;
      case aarch64:
        fmt = ExtraRegisters::NT_FPR;
        break;
    }
    ExtraRegisters extra_regs;
    if (!extra_regs.set_to_raw_data(
            rs.arch(), fmt, extra_register_raw.begin(),
            extra_register_raw.size(),
            xsave_layout_from_trace(task->trace_reader().cpuid_records()))) {
      FATAL() << "Invalid extended register data in trace";
    }
    return extra_regs;
  } else {
    return ExtraRegisters(rs.arch());
  }
}

static ExtraRegisters build_extra_regs(
    SupportedArch arch, const std::vector<CPUIDRecord>& cpuid_records,
    capnp::Data::Reader& extra_register_raw) {
  if (extra_register_raw.size()) {
    ExtraRegisters::Format fmt;
    switch (arch) {
      default:
        FATAL() << "Unknown architecture";
        RR_FALLTHROUGH;
      case x86:
      case x86_64:
        fmt = ExtraRegisters::XSAVE;
        break;
      case aarch64:
        fmt = ExtraRegisters::NT_FPR;
        break;
    }
    ExtraRegisters extra_regs;
    if (!extra_regs.set_to_raw_data(arch, fmt, extra_register_raw.begin(),
                                    extra_register_raw.size(),
                                    xsave_layout_from_trace(cpuid_records))) {
      FATAL() << "Invalid extended register data in trace";
    }
    return extra_regs;
  } else {
    return ExtraRegisters(arch);
  }
}

static bool is_auto_mapped(const KernelMapping& km) {
  return km.start() == AddressSpace::rr_page_start() ||
         km.start() == AddressSpace::preload_thread_locals_start() ||
         km.is_vsyscall();
}

static bool vdso_or_stack(const std::string& name) {
  return name.size() > 0 && name[0] == '[';
}

std::vector<DeserializedMapping> read_mappings(
    const rr::trace::TaskInfo::Reader& task_info_reader,
    bool* executable_map_found = nullptr) {
  auto mappings_data = task_info_reader.getMemoryMappings();
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
          km_data.getHasEmuFile() });
    }
  }
  return mappings;
}

static void setup_fd_table(Task* t, FdTable& fds, int tracee_socket_fd_number) {
  fds.add_monitor(
      t, STDOUT_FILENO,
      new StdioMonitor(t->session().tracee_output_fd(STDOUT_FILENO)));
  fds.add_monitor(
      t, STDERR_FILENO,
      new StdioMonitor(t->session().tracee_output_fd(STDERR_FILENO)));
  fds.add_monitor(t, 999, new MagicSaveDataMonitor());
  fds.add_monitor(t, tracee_socket_fd_number, new PreserveFileMonitor());
}

SerializedCheckpoint deserialize_clone_completion_into(ReplaySession& dest,
                                                       ScopedFd& checkpointFd) {
  DEBUG_ASSERT(dest.clone_completion == nullptr);

  capnp::PackedFdMessageReader datum(
      checkpointFd, {
                        .traversalLimitInWords = (8 * 1024 * 1024 * 8 * 8),
                        .nestingLimit = 64,
                    });
  trace::CloneCompletionInfo::Reader cc_reader =
      datum.getRoot<trace::CloneCompletionInfo>();
  const auto addr_spaces = cc_reader.getAddressSpaces();
  auto completion = std::unique_ptr<CloneCompletion>(new CloneCompletion());

  std::vector<CPUIDRecord> cpuid_records;
  auto first = true;
  std::vector<CloneCompletion::AddressSpaceClone> partial_init_addr_spaces;
  Task::ClonedFdTables cloned_fd_tables = {};
  for (const auto& as : addr_spaces) {
    const auto taskInfo = as.getCloneLeader();
    const auto taskCapturedState = as.getCloneLeaderState();
    ReplayTask* new_task = nullptr;
    if (first) {
      new_task = dest.current_task();
      first = false;
    } else {
      FATAL() << "We need to actually spawn a task here.";
      new_task =
          (ReplayTask*)dest.new_task(taskInfo.getTid(), taskInfo.getRecTid(),
                                     taskInfo.getSerial(), dest.arch());
    }
    new_task->vm()->remove_all_breakpoints();
    new_task->vm()->remove_all_watchpoints();
    new_task->is_stopped = true;
    new_task->new_os_exec_stub(dest.arch());
    Task::CapturedState cloneLeaderCaptureState =
        reconstitute(dest, new_task, as.getCloneLeaderState());

    auto register_raw = taskCapturedState.getRegs().getRaw();
    Registers regs{};
    SupportedArch arch;
    switch (taskInfo.getArch()) {
      case trace::Arch::X86:
        arch = SupportedArch::x86;
        break;
      case trace::Arch::X8664:
        arch = SupportedArch::x86_64;
        break;
      case trace::Arch::AARCH64:
        arch = SupportedArch::aarch64;
        break;
    }
    regs.set_arch(dest.arch());
    regs.set_from_trace(arch, register_raw.begin(), register_raw.size());
    auto extra_register_raw = taskCapturedState.getExtraRegs();
    if (cpuid_records.empty()) {
      cpuid_records = new_task->trace_reader().cpuid_records();
    }
    auto erraw = extra_register_raw.getRaw();
    ExtraRegisters extra_regs =
        build_extra_regs(dest.arch(), cpuid_records, erraw);

    bool executable_mapping_found = false;
    auto mappings = read_mappings(taskInfo, &executable_mapping_found);

    ASSERT(new_task, executable_mapping_found) << "No executable mapping?";
    auto sm_km = std::find_if(mappings.begin(), mappings.end(),
                              [](auto& map) { return map.km.is_stack(); });
    ASSERT(new_task, sm_km != std::end(mappings)) << "Could not find stack.";
    std::string exe_name = taskCapturedState.getPrname().asChars().begin();
    {
      new_task->post_exec(exe_name, exe_name);
      static_cast<Task*>(new_task)->post_exec_syscall();
      // new_task->set_regs(regs);
      ASSERT(new_task, !extra_regs.empty());
      // new_task->set_extra_regs(extra_regs);
    }
    // N.B. commented out; we will have to open our own files thus there will be
    // no file descriptors to close.
    // new_task->fd_table()->close_after_exec(new_task,
    // new_task->current_trace_frame().event().Syscall().exec_fds_to_close);
    {
      AutoRemoteSyscalls remote(new_task,
                                AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
      new_task->vm()->unmap_all_but_rr_page(remote);

      auto& stack_mapping = (*sm_km);
      map_region_no_file(remote, stack_mapping.km);
      bool write_ok = true;
      // new_task->write_mem<byte>(stack_mapping.start(), sm_km->second.ptr,
      // sm_km->second.size, &write_ok);
      auto bytes_written = new_task->write_bytes_helper_no_notifications(
          stack_mapping.km.start(), stack_mapping.size(), stack_mapping.data(),
          &write_ok);
      ASSERT(new_task, write_ok)
          << "Failed to write deserialized contents to memory map "
          << stack_mapping.km.str();
      ASSERT(new_task,
             static_cast<uint64_t>(bytes_written) == stack_mapping.size())
          << "Failed to deserialize contents into mapping. Wrote "
          << bytes_written << "; expected " << stack_mapping.size();
    }

    const auto& recorded_exe_name = exe_name;
    auto syscallbuffer_mapping =
        std::find_if(mappings.cbegin(), mappings.cend(), [&](auto& deser_map) {
          return deser_map.km.start() ==
                 cloneLeaderCaptureState.syscallbuf_child.cast<void>();
        });
    auto nosysbuf = syscallbuffer_mapping == std::cend(mappings);
    //  ASSERT(new_task, syscallbuffer_mapping != std::cend(mappings)) << "Could
    //  not find syscallbuffer mapping in deserialized contents";
    std::vector<DeserializedMapping*> mappings_with_emufiles;
    {
      AutoRemoteSyscalls remote(new_task);
      for (auto map_index = 0u; map_index < mappings.size() - 1; ++map_index) {
        if (mappings[map_index].km == syscallbuffer_mapping->km) {
          printf("skipping syscall buffer mapping. Let rr handle it\n");
          continue;
        }
        if (mappings[map_index].km.start() ==
            AddressSpace::preload_thread_locals_start()) {
          printf("thread_locals mapping found\n");
          // thread_locals = &mappings[map_index];
          continue;
        }
        if (mappings[map_index].km.start() == AddressSpace::rr_page_start()) {
          printf("rr_preload mapping found\n");
          // rr_preload = &mappings[map_index];
          continue;
        }
        bool write_ok = true;
        map_region_no_file(remote, mappings[map_index].km);
        auto bytes_written = new_task->write_bytes_helper_no_notifications(
            mappings[map_index].km.start(), mappings[map_index].size(),
            mappings[map_index].data(), &write_ok);
        ASSERT(new_task, write_ok)
            << "Failed to write deserialized contents to memory map "
            << mappings[map_index].km.str();
        ASSERT(new_task, static_cast<uint64_t>(bytes_written) ==
                             mappings[map_index].size())
            << "Failed to deserialize contents into mapping. Wrote "
            << bytes_written << "; expected " << mappings[map_index].size();
        // new_task->write_mem<byte>(mappings[i].first.start(),
        // mappings[i].second.ptr, mappings[i].second.size, &write_ok);
        if (mappings[map_index].hasEmu) {
          mappings_with_emufiles.push_back(&mappings[map_index]);
        }
      }
      auto index = recorded_exe_name.rfind('/');
      auto name = "rr:" + recorded_exe_name.substr(
                              index = std::string::npos ? 0 : index + 1);
      AutoRestoreMem mem(remote, name.c_str());
      remote.infallible_syscall(syscall_number_for_prctl(new_task->arch()),
                                PR_SET_NAME, mem.get());
    }

    auto scratchPointer = remote_ptr<void>(taskCapturedState.getScratchPtr());
    ASSERT(new_task, scratchPointer != nullptr) << "No scratch pointer found!";
    auto scratch_mem =
        std::find_if(mappings.begin(), mappings.end(), [&](auto& map) {
          return map.km.contains(scratchPointer);
        });
    ASSERT(new_task, scratch_mem != std::end(mappings))
        << "Scratch memory mapping could not be restored.";
    init_scratch_memory(new_task, scratch_mem->km);
    new_task->write_bytes_ptrace(scratch_mem->km.start(), scratch_mem->size(),
                                 scratch_mem->data());
    slow_verify_syscall_buffer_contents(new_task, *scratch_mem,
                                        "scratch memory");
    // new_task->apply_all_data_records_from_trace();
    // Since we copy the entire VMA Space, do we need to do this?
    // new_task->vm()->save_auxv(new_task);
    {
      if (!nosysbuf) {
        printf("Syscall buffer enabled (found in serialized contents)\n");
        auto& sysbuf_map = *syscallbuffer_mapping;
        new_task->init_buffers_arch_pcp(
            cloneLeaderCaptureState.syscallbuf_child,
            cloneLeaderCaptureState.cloned_file_data_fname,
            cloneLeaderCaptureState.desched_fd_child,
            cloneLeaderCaptureState.cloned_file_data_fd_child,
            cloneLeaderCaptureState.syscallbuf_size, (void*)sysbuf_map.data(),
            sysbuf_map.size());
        // new_task->init_buffers(taskCapturedState.getSyscallbufChild());
        syscall(SYS_rrcall_reload_auxv, new_task->tid);
        slow_verify_syscall_buffer_contents(new_task, sysbuf_map,
                                            "syscall buffer");
      }
    }
    new_task->set_regs(regs);
    ASSERT(new_task, !extra_regs.empty());
    new_task->set_extra_regs(extra_regs);
    std::vector<Task::CapturedState> member_states;
    using ByteVector = std::vector<Byte>;
    std::vector<std::pair<remote_ptr<void>, ByteVector>> captured_memory;
    for (auto member_state : as.getMemberState()) {
      member_states.push_back(reconstitute(dest, new_task, member_state));
    }
    for (auto captured_mem : as.getCapturedMemory()) {
      ByteVector mem;
      auto mem_reader = captured_mem.getData();
      mem.reserve(mem_reader.size());
      std::copy(mem_reader.begin(), mem_reader.begin() + mem_reader.size(),
                std::back_inserter(mem));
      captured_memory.push_back(
          std::make_pair(captured_mem.getStartAddress(), std::move(mem)));
    }
    auto fd_table_key = cloneLeaderCaptureState.fdtable_identity;
    partial_init_addr_spaces.push_back(CloneCompletion::AddressSpaceClone{
        .clone_leader = new_task,
        .clone_leader_state = std::move(cloneLeaderCaptureState),
        .member_states = std::move(member_states),
        .captured_memory = std::move(captured_memory) });
    dest.on_create(new_task);
    new_task->fds = FdTable::create(new_task);
    for (const auto map : mappings_with_emufiles) {
      auto emu = dest.emufs().get_or_create(map->km);
      if (!new_task->fd_table()->is_monitoring(emu->fd().get())) {
        new_task->fd_table()->add_monitor(
            new_task, emu->fd().get(), new MmappedFileMonitor{ new_task, emu });
      }
    }
    auto fd_table = new_task->fd_table();
    if (fd_table->get_monitor(1)) {
      printf("FdTable already has setup\n");
    } else {
      printf("FdTable already has not been setup. Setting up.\n");
      setup_fd_table(new_task, *fd_table, dest.tracee_socket_fd_number);
    }
    cloned_fd_tables[fd_table_key] = fd_table;
  } // end of 1 clone leader setup iteration

  dest.clone_completion = std::make_unique<CloneCompletion>();
  dest.clone_completion->address_spaces = std::move(partial_init_addr_spaces);
  dest.clone_completion->cloned_fd_tables = std::move(cloned_fd_tables);
  memcpy(&dest.current_step, cc_reader.getSessionCurrentStep().begin(),
         sizeof(ReplayTraceStep));

  SerializedCheckpoint cp;
  {
    auto checkpointReader = cc_reader.getCheckpoint();
    auto proto_mark = checkpointReader.getProto();
    auto extra_regs = checkpointReader.getExtraRegs().getRaw();

    auto register_raw = proto_mark.getRegs();
    auto regs = Registers{ dest.arch() };
    regs.set_from_trace(dest.arch(), register_raw.getRaw().begin(),
                        register_raw.getRaw().size());

    cp.is_explicit = checkpointReader.getExplicit();
    cp.last_continue_tuid =
        TaskUid(checkpointReader.getLastContinueTuid().getPid(),
                checkpointReader.getLastContinueTuid().getSerial());
    cp.where = data_to_str(checkpointReader.getWhere());
    cp.key = MarkKey{ .trace_time = proto_mark.getKey().getTraceTime(),
                      .ticks = proto_mark.getKey().getTicks(),
                      .step_key = (int)proto_mark.getKey().getStepKey() };
    cp.regs = regs;
    cp.return_addresses = ReturnAddressList();
    auto i = 0;
    for (const auto& ra : proto_mark.getReturnAddresses()) {
      cp.return_addresses.addresses[i++] = ra;
    }

    cp.extra_regs = build_extra_regs(dest.arch(), cpuid_records, extra_regs);
    cp.ticks_at_event_start = checkpointReader.getTicksAtEventStart();
    cp.singlestep_to_next_mark_no_signal =
        checkpointReader.getSinglestepToNextMarkNoSignal();
  }

  dest.trace_reader().rewind();
  dest.trace_reader().forward_to(cp.key.trace_time);
  // dest.trace_reader().set_readers_offset(trace_reader_offset);
  dest.trace_frame = dest.trace_reader().read_frame();
  return cp;
}

static auto write_capture_state(const Task::CapturedState& state,
                                trace::CapturedState::Builder& ms) {
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

// since we're not C++20, we unfortunately can't use auto in fn params. Using
// templates instead.
template <typename MemberStateBuilder>
static void write_members_capture_states(
    MemberStateBuilder& builder,
    const std::vector<Task::CapturedState>& member_states) {
  auto count = 0;
  for (const auto& state : member_states) {
    auto ms = builder[count++];
    write_capture_state(state, ms);
  }
}

template <typename CapturedMemoryBuilder>
static void write_captured_memory(CapturedMemoryBuilder& builder,
                                  const CapturedMemory& captured_memory) {
  auto count = 0;
  for (const auto& mem : captured_memory) {
    auto cm = builder[count++];
    cm.setStartAddress(mem.first.as_int());
    capnp::Data::Builder v{ const_cast<unsigned char*>(mem.second.data()),
                            mem.second.size() };
    cm.setData(v);
  }
}

void serialize_clone_completion(ReplaySession& cloned_session,
                                const std::string& trace_dir,
                                const std::string& file,
                                const SerializedCheckpoint& cp) {
  const auto is_auto_mapped = [](const auto& km) {
    return km.start() == AddressSpace::rr_page_start() ||
           km.start() == AddressSpace::preload_thread_locals_start() ||
           km.is_vsyscall();
  };

  DEBUG_ASSERT(cloned_session.clone_completion != nullptr);
  capnp::MallocMessageBuilder message;
  auto fd = create_new_exclusive(file.c_str());
  auto cc = message.initRoot<trace::CloneCompletionInfo>();

  auto cpBuilder = cc.initCheckpoint();
  cpBuilder.initExtraRegs().setRaw(extra_regs_to_raw(cp.extra_regs));

  auto proto = cpBuilder.initProto();
  proto.initRegs().setRaw(regs_to_raw(cp.regs));
  auto key = proto.initKey();
  key.setTicks(cp.key.ticks);
  key.setTraceTime(cp.key.trace_time);
  key.setStepKey(cp.key.step_key);
  auto ras = proto.initReturnAddresses(8);
  for (auto i = 0; i < 8; i++) {
    ras.set(i, cp.return_addresses.addresses[i].as_int());
  }

  cpBuilder.setTicksAtEventStart(cp.ticks_at_event_start);
  cpBuilder.setExplicit(cp.is_explicit);
  cpBuilder.setSinglestepToNextMarkNoSignal(
      cp.singlestep_to_next_mark_no_signal);
  cpBuilder.setWhere(str_to_data(cp.where));

  auto lct = cpBuilder.initLastContinueTuid();
  lct.setPid(cp.last_continue_tuid.tid());
  lct.setSerial(cp.last_continue_tuid.serial());

  auto addr_space_count =
      cloned_session.clone_completion->address_spaces.size();
  auto& as_data = cloned_session.clone_completion->address_spaces;
  capnp::List<trace::AddressSpaceClone>::Builder asc =
      cc.initAddressSpaces(addr_space_count);
  for (auto i = 0u; i < addr_space_count; i++) {
    const auto& as = as_data[i];
    // ASSERT(as.clone_leader, as.clone_leader->regs().matches(cp.regs)) <<
    // "Clone leader registers not the same as checkpoint!";
    auto b_as = asc[i];
    auto cls = b_as.initCloneLeaderState();
    write_capture_state(as.clone_leader_state, cls);
    auto clone_leader = asc[i].initCloneLeader();
    clone_leader.setTid(as.clone_leader->tid);
    clone_leader.setRecTid(as.clone_leader->rec_tid);
    clone_leader.setSerial(as.clone_leader_state.serial);
    clone_leader.setArch(to_trace_arch(as.clone_leader->arch()));
    clone_leader.initRegisters().setRaw(regs_to_raw(as.clone_leader->regs()));
    clone_leader.initExtraRegisters().setRaw(
        extra_regs_to_raw(as.clone_leader->extra_regs()));

    auto maps = as.clone_leader->vm()->maps();
    auto begin = maps.begin();
    auto count = 0u;
    while (begin != maps.end()) {
      ++count;
      ++begin;
    }
    auto kernel_mappings = clone_leader.initMemoryMappings(count);
    auto map_index = 0u;
    auto data_dir =
        trace_dir + "/" + "checkpoint-" + std::to_string(cp.key.trace_time);
    printf("Checkpoint data directory: %s\n", data_dir.c_str());
    KernelMapWriter map_writer{ as.clone_leader, data_dir };

    for (const auto& map : as.clone_leader->vm()->maps()) {
      if (!is_auto_mapped(map.map) && !is_auto_mapped(map.recorded_map)) {
        ASSERT(as.clone_leader, map.map == map.recorded_map);
        auto km = kernel_mappings[map_index++];
        km.setStart(map.map.start().as_int());
        km.setEnd(map.map.end().as_int());
        km.setFsname(str_to_data(map.recorded_map.fsname()));
        km.setDevice(map.map.device());
        km.setInode(map.map.inode());
        km.setProtection(map.map.prot());
        km.setFlags(map.map.flags());
        km.setOffset(map.map.file_offset_bytes());
        km.setHasEmuFile(map.emu_file != nullptr);
        const auto path = map_writer.write_map(map.map);
        km.setContentsPath(str_to_data(path));
        km.setRrSysMap(0);
      }
    }

    auto b_captured_mem_list =
        b_as.initCapturedMemory(as.captured_memory.size());
    write_captured_memory(b_captured_mem_list, as.captured_memory);

    auto member_states_builder = b_as.initMemberState(as.member_states.size());
    write_members_capture_states(member_states_builder, as.member_states);
  }
  auto step = capnp::Data::Reader{ (Byte*)&cloned_session.current_step, 32 };
  cc.setSessionCurrentStep(step);
  capnp::writePackedMessageToFd(fd->get(), message);
}

} // namespace rr