#pragma once

#include <sys/time.h>
#include "GdbServer.h"
#include "rr_pcp.capnp.h"
#include "util.h"

namespace rr {

using CPUIdRecords = std::vector<CPUIDRecord>;

// Data transformation from what used to be GdbServer::Checkpoint <= CheckpointInfo => capnproto
// Contains the Checkpoint data, as well as the path to the CloneCompletion file
class CheckpointInfo {
public:
  CheckpointInfo(const Checkpoint& checkpoint);
  CheckpointInfo(std::string info_file, FrameTime time, size_t unique_id, const Checkpoint& checkpoint);
  CheckpointInfo(rr::trace::CheckpointInfo::Reader reader, SupportedArch arch, const std::vector<CPUIDRecord>& cpuid_recs);

  bool exists_on_disk() const;
  void delete_from_disk();

  static size_t generate_unique_id() {
    timeval t;
    gettimeofday(&t, nullptr);
    auto cp_id = (t.tv_sec * 1000 + t.tv_usec / 1000);
    return cp_id;
  }

  friend bool operator==(const CheckpointInfo& lhs, const CheckpointInfo& rhs) {
    return lhs.info_file == rhs.info_file;
  }

  std::string info_file;
  FrameTime time;
  size_t unique_id;
  TaskUid last_continue_tuid;
  Ticks ticks;
  int step_key;
  Registers regs;
  ReturnAddressList return_addresses;
  ExtraRegisters extra_regs;
  Ticks ticks_at_event_start;
  bool singlestep_to_next_mark_no_signal;
  std::string where;
};

/**
 * Returns the path of checkpoint index file, given the dir |trace_dir|
 */
std::string checkpoints_index_file(const std::string& trace_dir);

/**
 * Retrieve list of persistent checkpoints in |trace_dir| sorted by event time.
 */
std::vector<CheckpointInfo> get_checkpoint_infos(const std::string& trace_dir, SupportedArch arch, const CPUIdRecords& cpuid_recs);

/**
 * Updates the index for serialized checkpoints on disk to contain the |checkpoints|.
 */
void update_serialized_checkpoints(const std::string& trace_dir, SupportedArch arch, const std::vector<CPUIDRecord>& cpuid_recs, const std::vector<CheckpointInfo>& checkpoints);

} // namespace rr