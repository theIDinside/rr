#include "CheckpointInfo.h"
#include "ExtraRegisters.h"
#include "ReturnAddressList.h"
#include "rr_pcp.capnp.h"
#include "stream_util.h"
#include <algorithm>
#include <capnp/blob.h>
#include <capnp/message.h>
#include <capnp/serialize-packed.h>

namespace rr {

//XXX: Read the CheckpointInfo from the main checkpoints metadata file. Currently depends on |SupportedArch| and |CPUIDRecords| for
// restoring |Register|'s and |ExtraRegister|'s which is not nice. This should just have to take `trace_dir`.
std::vector<CheckpointInfo> get_checkpoint_infos(const std::string& trace_dir, SupportedArch arch, const std::vector<CPUIDRecord>& cpuid_recs) {
  // the trace's main checkpoint file, containing the list of all persistent checkpoints.
  const auto path = checkpoints_index_file(trace_dir);
  ScopedFd fd(path.c_str(), O_RDONLY);
  std::vector<CheckpointInfo> checkpoints;
  if (!fd.is_open()) {
    return checkpoints;
  }
  capnp::PackedFdMessageReader reader(fd);
  trace::PersistentCheckpoints::Reader checkpointsInfoReader = reader.getRoot<trace::PersistentCheckpoints>();
  auto cps = checkpointsInfoReader.getCheckpoints();
  for (auto cp : cps) {
    auto info = CheckpointInfo { cp, arch, cpuid_recs };
    if (info.exists_on_disk()) {
      checkpoints.push_back(info);
    }
  }
  std::sort(checkpoints.begin(), checkpoints.end(),
            [](auto& a, auto& b) { return a.time <= b.time; });
  return checkpoints;
}

bool CheckpointInfo::exists_on_disk() const {
  struct stat buf;
  return stat(info_file.c_str(), &buf) == 0 &&
         stat((info_file + std::to_string(time)).c_str(), &buf) == 0;
}

CheckpointInfo::CheckpointInfo(const Checkpoint& c)
    : time(c.mark.time()),
      unique_id(c.unique_id == 0 ? CheckpointInfo::generate_unique_id()
                                 : c.unique_id),
      last_continue_tuid(c.last_continue_tuid),
      ticks(c.mark.ticks()),
      step_key(c.mark.step_key()),
      regs(c.mark.regs()),
      return_addresses(c.mark.get_internal()->proto.return_addresses),
      extra_regs(c.mark.extra_regs()),
      ticks_at_event_start(c.mark.get_internal()->ticks_at_event_start),
      singlestep_to_next_mark_no_signal(c.mark.get_internal()->singlestep_to_next_mark_no_signal),
      where(c.where) {
        info_file = c.mark.get_internal()->checkpoint->trace_reader().dir() + "/checkpoint-" + std::to_string(unique_id);
      }

CheckpointInfo::CheckpointInfo(std::string info_file, FrameTime time,
                               size_t unique_id, const Checkpoint& cp)
    : info_file{ std::move(info_file) },
      time{ time },
      unique_id{ unique_id },
      last_continue_tuid{ cp.last_continue_tuid },
      ticks{ cp.mark.ticks() },
      step_key{ cp.mark.step_key() },
      regs{ cp.mark.regs() },
      return_addresses{ cp.mark.get_internal()->proto.return_addresses },
      extra_regs{ cp.mark.extra_regs() },
      ticks_at_event_start{ cp.mark.get_internal()->ticks_at_event_start },
      singlestep_to_next_mark_no_signal{
        cp.mark.get_internal()->singlestep_to_next_mark_no_signal
      },
      where{ cp.where } {}

CheckpointInfo::CheckpointInfo(rr::trace::CheckpointInfo::Reader reader, SupportedArch arch, const std::vector<CPUIDRecord>& cpuid_recs)
    : info_file(data_to_str(reader.getCloneCompletionFile())),
      time(reader.getTime()),
      unique_id(reader.getId()),
      last_continue_tuid(reader.getLastContinueTuid().getPid(),
                         reader.getLastContinueTuid().getSerial()),
      ticks(reader.getTicks()),
      step_key(reader.getStepKey()),
      regs(),
      return_addresses(),
      extra_regs(),
      ticks_at_event_start(reader.getTicksAtEventStart()),
      singlestep_to_next_mark_no_signal(
          reader.getSinglestepToNextMarkNoSignal()),
      where(data_to_str(reader.getWhere())) {
    regs.set_arch(arch);
    regs.set_from_trace(arch, reader.getRegs().getRaw().begin(), reader.getRegs().getRaw().size());
    auto eregs = reader.getExtraRegs().getRaw();
    set_extra_regs_from_raw(arch, cpuid_recs, eregs, extra_regs);
  auto i = 0;
  for (auto rs : reader.getReturnAddresses()) {
    return_addresses.addresses[i++] = rs;
  }
}

void CheckpointInfo::delete_from_disk() {
  const auto remove_file = [](auto map) {
    const auto path = data_to_str(map.getContentsPath());
    if (remove(path.c_str()) != 0) {
      LOG(error) << "Failed to remove " << path;
    }
  };
  ScopedFd fd(info_file.c_str(), O_RDONLY);
  capnp::PackedFdMessageReader datum(fd);
  trace::CloneCompletionInfo::Reader cc_reader =
      datum.getRoot<trace::CloneCompletionInfo>();
  const auto addr_spaces = cc_reader.getAddressSpaces();
  for (const auto& as : addr_spaces) {
    const auto mappings_data = as.getCloneLeader().getVirtualAddressSpace();
    for(const auto& m : mappings_data) {
      switch(m.getMapType().which()) {
        case trace::KernelMapping::MapType::FILE:
          remove_file(m.getMapType().getFile());
          break;
        case trace::KernelMapping::MapType::SHARED_ANON:
          remove_file(m.getMapType().getSharedAnon());
          break;
        case trace::KernelMapping::MapType::PRIVATE_ANON:
          remove_file(m.getMapType().getPrivateAnon());
          break;
        case trace::KernelMapping::MapType::GUARD_SEGMENT:
          break;
      }
    }
  }

  remove(info_file.c_str());
  remove((info_file + std::to_string(time)).c_str());
  if (exists_on_disk()) {
    LOG(error) << "Couldn't remove persistent checkpoint data (or directory)";
  }
}
} // namespace rr