#include "CheckpointInfo.h"
#include "ReplayTimeline.h"
#include "ScopedFd.h"
#include "stream_util.h"
#include <algorithm>
#include <capnp/blob.h>
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <cstddef>

namespace rr {

MarkData::MarkData(const ReplayTimeline::Mark& m)
    : time(m.get_key().trace_time),
      ticks(m.get_key().ticks),
      step_key(m.get_key().step_key.as_int()),
      ticks_at_event_start(m.get_internal()->ticks_at_event_start),
      regs(m.regs()),
      extra_regs(m.extra_regs()),
      return_addresses(m.get_internal()->proto.return_addresses),
      singlestep_to_next_mark_no_signal(
          m.get_internal()->singlestep_to_next_mark_no_signal) {}

MarkData::MarkData(rr::pcp::MarkData::Reader reader, SupportedArch arch,
                   const CPUIDRecords& cpuid_recs)
    : time(reader.getTime()),
      ticks(reader.getTicks()),
      step_key(reader.getStepKey()),
      ticks_at_event_start(reader.getTicksAtEventStart()),
      regs(),
      extra_regs(),
      return_addresses(),
      singlestep_to_next_mark_no_signal(
          reader.getSinglestepToNextMarkNoSignal()) {
  regs.set_arch(arch);
  regs.set_from_trace(arch, reader.getRegs().getRaw().begin(),
                      reader.getRegs().getRaw().size());
  auto eregs = reader.getExtraRegs().getRaw();
  set_extra_regs_from_raw(arch, cpuid_recs, eregs, extra_regs);
  auto i = 0;
  for (auto rs : reader.getReturnAddresses()) {
    return_addresses.addresses[i++] = rs;
  }
}

std::vector<CheckpointInfo> get_checkpoint_infos(const std::string& trace_dir, SupportedArch arch, const CPUIDRecords& cpuid_recs) {
  // the trace's main checkpoint file, containing the list of all persistent
  // checkpoints.
  const auto path = checkpoints_index_file(trace_dir);
  ScopedFd fd(path.c_str(), O_RDONLY);
  std::vector<CheckpointInfo> checkpoints;
  if (!fd.is_open()) {
    return checkpoints;
  }

  capnp::PackedFdMessageReader reader(fd);
  auto checkpointsInfoReader = reader.getRoot<pcp::PersistentCheckpoints>();
  auto cps = checkpointsInfoReader.getCheckpoints();
  for (const auto& cp : cps) {
    auto info = CheckpointInfo{ cp, arch, cpuid_recs };
    if (info.exists_on_disk()) {
      checkpoints.push_back(info);
    }
  }
  std::sort(checkpoints.begin(), checkpoints.end(),
            [](CheckpointInfo& a, CheckpointInfo& b) {
              return a.clone_data.time <= b.clone_data.time;
            });
  return checkpoints;
}

bool CheckpointInfo::exists_on_disk() const {
  struct stat buf;
  return stat(capnp_cp_file.c_str(), &buf) == 0 &&
         stat((capnp_cp_file + std::to_string(clone_data.time)).c_str(), &buf) == 0;
}

CheckpointInfo::CheckpointInfo(const Checkpoint& c)
    : unique_id(CheckpointInfo::generate_unique_id(c.unique_id)),
      last_continue_tuid(c.last_continue_tuid),
      where(c.where),
      clone_data(c.mark),
      non_explicit_mark_data(nullptr)
      {
  DEBUG_ASSERT(c.is_explicit == Checkpoint::EXPLICIT && c.mark.has_rr_checkpoint());
  // can't assert before ctor, set these values here.
  next_serial = c.mark.get_checkpoint()->current_task_serial();
  stats = c.mark.get_checkpoint()->statistics();
  LOG(debug) << "checkpoint clone at " << clone_data.time
               << "; GDB checkpoint at " << clone_data.time;
  capnp_cp_file = c.mark.get_checkpoint()->trace_reader().dir() +
              "/checkpoint-" + std::to_string(unique_id);
}

CheckpointInfo::CheckpointInfo(TaskUid last_continue,
                               const ReplayTimeline::Mark& mark_with_checkpoint)
    : unique_id(CheckpointInfo::generate_unique_id()),
      last_continue_tuid(last_continue),
      where("Unknown"),
      next_serial(mark_with_checkpoint.get_checkpoint()->current_task_serial()),
      clone_data(mark_with_checkpoint),
      non_explicit_mark_data(nullptr),
      stats(mark_with_checkpoint.get_checkpoint()->statistics())
{
  LOG(debug) << "checkpoint clone at " << clone_data.time
               << "; GDB checkpoint at " << clone_data.time;
  capnp_cp_file = mark_with_checkpoint.get_checkpoint()->trace_reader().dir() +
                  "/checkpoint-" + std::to_string(unique_id);
}

CheckpointInfo::CheckpointInfo(const Checkpoint& non_explicit_cp,
                               const ReplayTimeline::Mark& mark_with_clone)
    : unique_id(CheckpointInfo::generate_unique_id(non_explicit_cp.unique_id)),
      last_continue_tuid(non_explicit_cp.last_continue_tuid),
      where(non_explicit_cp.where),
      next_serial(
          mark_with_clone.get_checkpoint()->current_task_serial()),
      clone_data(mark_with_clone),
      non_explicit_mark_data(new MarkData{ non_explicit_cp.mark }),
      stats(mark_with_clone.get_checkpoint()->statistics()) {
  DEBUG_ASSERT(non_explicit_cp.is_explicit == Checkpoint::NOT_EXPLICIT &&
               !non_explicit_cp.mark.has_rr_checkpoint() &&
               "Constructor meant for non explicit checkpoints");
  // XXX we give this checkpoint the id (and name/path) of the actual cloned session
  // data, so that multiple non explicit checkpoints later on, can reference the
  // same clone data (not yet implemented)
  LOG(debug) << "checkpoint clone at " << clone_data.time << "; GDB checkpoint at " << non_explicit_mark_data->time;
  capnp_cp_file = mark_with_clone.get_checkpoint()->trace_reader().dir() +
              "/checkpoint-" + std::to_string(unique_id);
}

CheckpointInfo::CheckpointInfo(rr::pcp::CheckpointInfo::Reader reader,
                               SupportedArch arch,
                               const CPUIDRecords& cpuid_recs)
    : capnp_cp_file(data_to_str(reader.getCloneCompletionFile())),
      unique_id(reader.getId()),
      last_continue_tuid(reader.getLastContinueTuid().getTid(),
                         reader.getLastContinueTuid().getSerial()),
      where(data_to_str(reader.getWhere())),
      next_serial(reader.getNextSerial()),
      clone_data(reader.isExplicit() ? reader.getExplicit()
                                     : reader.getNonExplicit().getCloneMark(),
                 arch, cpuid_recs),
      non_explicit_mark_data(
          reader.isNonExplicit()
              ? new MarkData{ reader.getNonExplicit().getCheckpointMark(), arch,
                              cpuid_recs }
              : nullptr),
      stats() {
      auto s = reader.getStatistics();
      stats.bytes_written = s.getBytesWritten();
      stats.syscalls_performed = s.getSyscallsPerformed();
      stats.ticks_processed = s.getTicksProcessed();
}

void CheckpointInfo::delete_from_disk() {
  const auto remove_file = [](auto path_data) {
    const auto path = data_to_str(path_data);
    if (remove(path.c_str()) != 0) {
      LOG(error) << "Failed to remove " << path;
    }
  };
  ScopedFd fd(capnp_cp_file.c_str(), O_RDONLY);
  capnp::PackedFdMessageReader datum(fd);
  pcp::CloneCompletionInfo::Reader cc_reader =
      datum.getRoot<pcp::CloneCompletionInfo>();
  const auto addr_spaces = cc_reader.getAddressSpaces();
  for (const auto& as : addr_spaces) {
    const auto mappings_data = as.getProcessSpace().getVirtualAddressSpace();
    for (const auto& m : mappings_data) {
      switch (m.getMapType().which()) {
        case pcp::KernelMapping::MapType::FILE:
          remove_file(m.getMapType().getFile().getContentsPath());
          break;
        case pcp::KernelMapping::MapType::SHARED_ANON:
          remove_file(m.getMapType().getSharedAnon().getContentsPath());
          break;
        case pcp::KernelMapping::MapType::PRIVATE_ANON:
          remove_file(m.getMapType().getPrivateAnon().getContentsPath());
          break;
        case pcp::KernelMapping::MapType::GUARD_SEGMENT:
          break;
        case pcp::KernelMapping::MapType::SYSCALL_BUFFER:
          remove_file(m.getMapType().getSyscallBuffer().getContentsPath());
          break;
        case pcp::KernelMapping::MapType::RR_PAGE:
          remove_file(m.getMapType().getRrPage().getContentsPath());
          break;
      }
    }
  }

  remove(capnp_cp_file.c_str());
  remove(data_directory().c_str());
  if (exists_on_disk()) {
    LOG(error) << "Couldn't remove persistent checkpoint data (or directory)";
  }
}

ScopedFd CheckpointInfo::open_for_read() const {
  DEBUG_ASSERT(exists_on_disk() && "This checkpoint has not been serialized; or the index file has been removed.");
  auto file = ScopedFd(capnp_cp_file.c_str(), O_RDONLY);
  if (!file.is_open()) FATAL() << "Couldn't open checkpoint data " << file;
  return file;
}

ScopedFd CheckpointInfo::open_for_write() const {
  DEBUG_ASSERT(!exists_on_disk() && "Already serialized checkpoints shouldn't be re-written");
  auto file = ScopedFd(capnp_cp_file.c_str(), O_EXCL | O_CREAT | O_RDWR, 0700);
  if (!file.is_open()) FATAL() << "Couldn't open checkpoint file for writing " << file;
  return file;
}

std::string CheckpointInfo::data_directory() const {
  return capnp_cp_file + std::to_string(clone_data.time);
}

/*static*/ size_t CheckpointInfo::generate_unique_id(size_t id) {
    // if we haven't been set already, generate a unique "random" id
    if (id == 0) {
      timeval t;
      gettimeofday(&t, nullptr);
      auto cp_id = (t.tv_sec * 1000 + t.tv_usec / 1000);
      return cp_id;
    } else {
      return id;
    }
  }

} // namespace rr