#pragma once

#include "ExtraRegisters.h"
#include "GdbServer.h"
#include "ReturnAddressList.h"
#include "rr_pcp.capnp.h"
#include "util.h"
#include <sys/time.h>

namespace rr {

using CPUIDRecords = std::vector<CPUIDRecord>;

/**
 * CheckpointInfo and MarkData are intermediary types between de/serialization
 * of checkpoints and marks. These types are added to not intrude in Checkpoint,
 * Mark, InternalMarks, ProtoMark etc, to make sure that the implementation of
 * persistent checkpoints do not break any guarantees or invariants provided by
 * those types in normal record/replay.
 */

/**
 * `MarkData` flattens that "hierarchy" representing `Mark`, `InternalMark` and
 * `ProtoMark` required for de/serialization. When deserializing this hierarchy
 * is rebuilt from `MarkData`
 */
struct MarkData {
  // Constructor when serializing
  MarkData(const ReplayTimeline::Mark& m);
  // Constructor when de-serializing
  MarkData(rr::pcp::MarkData::Reader reader, SupportedArch arch,
           const CPUIDRecords& cpuid_recs);

  FrameTime time;
  Ticks ticks;
  int step_key;
  Ticks ticks_at_event_start;
  Registers regs;
  ExtraRegisters extra_regs;
  ReturnAddressList return_addresses;
  bool singlestep_to_next_mark_no_signal;
};

class CheckpointInfo {
public:
  /**
   * For `GDBServer` users of explicit checkpoints.
   */
  CheckpointInfo(const Checkpoint& checkpoint);

  /**
   * For `GDBServer` users where a non explicit checkpoint was set.
   * `mark_with_clone` is the mark which holds the actual checkpoint / clone,
   * which is some arbitrary event time before actual GDB checkpoint.
   */
  CheckpointInfo(const Checkpoint& checkpoint,
                 const ReplayTimeline::Mark& mark_with_clone);

  /* For `CreateCheckpointsCommand` users (rr create-checkpoints command) */
  CheckpointInfo(TaskUid last_continue_tuid,
                 const ReplayTimeline::Mark& mark_with_checkpoint);
  // When deserializing from capnproto stream
  CheckpointInfo(rr::pcp::CheckpointInfo::Reader reader, SupportedArch arch,
                 const CPUIDRecords& cpuid_recs);

  bool exists_on_disk() const;
  void delete_from_disk();

  ScopedFd open_for_read() const;
  ScopedFd open_for_write() const;

  /* Returns directory where the checkpoints memory mappings gets written to */
  std::string data_directory() const;

  /**
   * Returns event time for this checkpoint
   */
  FrameTime event_time() const { return clone_data.time; }

  static size_t generate_unique_id(size_t id = 0);

  friend bool operator==(const CheckpointInfo& lhs, const CheckpointInfo& rhs) {
    return lhs.capnp_cp_file == rhs.capnp_cp_file;
  }

  bool is_explicit() const { return non_explicit_mark_data == nullptr; }

  // Path to file containing filled out capnproto schema for this checkpoint
  std::string capnp_cp_file;
  size_t unique_id;
  TaskUid last_continue_tuid;
  std::string where;
  uint32_t next_serial;
  // MarkData collected from a Mark with a clone (either an explicit checkpoint,
  // or the first found clone before a non-explicit checkpoint)
  MarkData clone_data;
  // (optional) MarkData collected from a Mark without a clone (in the case of non explicit checkpoints)
  std::shared_ptr<MarkData> non_explicit_mark_data;
  Session::Statistics stats;
};

/**
 * Returns the path of checkpoint index file, given the dir `trace_dir`
 */
std::string checkpoints_index_file(const std::string& trace_dir);

/**
 * Retrieve list of persistent checkpoints in `trace_dir` sorted in ascending
 * order by event time.
 */
std::vector<CheckpointInfo> get_checkpoint_infos(
    const std::string& trace_dir, SupportedArch arch,
    const CPUIDRecords& cpuid_recs);

/**
 * Updates the index for serialized checkpoints on disk to contain the
 * `checkpoints`. Removes any checkpoints on disk, not found in `checkpoints`.
 * One can clear all persistent checkpoints on disk by calling this with an
 * empty `checkpoints`
 */
void update_persistent_checkpoint_index(
    const std::string& trace_dir, SupportedArch arch,
    const CPUIDRecords& cpuid_recs,
    const std::vector<CheckpointInfo>& checkpoints);

} // namespace rr