#pragma once

#include "AddressSpace.h"
#include "ExtraRegisters.h"
#include "Registers.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "ReturnAddressList.h"
#include "TaskishUid.h"
#include "TraceFrame.h"
#include "log.h"
#include "rr_pcp.capnp.h"
#include <capnp/blob.h>
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <kj/common.h>
#include "CheckpointInfo.h"
namespace rr {

using Byte = std::uint8_t;
using FrameTime = int64_t;

// Capnproto utilities

void write_capture_state(trace::CapturedState::Builder& ms, const Task::CapturedState& state);

/**
 * Writes the VM address space of |clone_leader| using the Capnproto |builder|. Checkpoint specific data,
 * like the serialized segments are stored in |checkpoint_data_dir|
 */
void write_vm(Task* clone_leader, rr::trace::CloneLeader::Builder builder, const std::string& checkpoint_data_dir);

/**
 * Write file |monitor| information to capnproto |builder|
 */
void write_monitor(rr::trace::FileMonitor::Builder& builder, int fd, FileMonitor* monitor);

Task::CapturedState reconstitute_captured_state(ReplaySession& s, trace::CapturedState::Reader reader);

// Re-factor this.
class DeserializedMapping {
public:
  DeserializedMapping(const KernelMapping& km,
                      std::string map_contents_filename, bool has_emu, bool is_sysv_segment);
  // Some mapppings are mapped and then get the contents copied over
  std::vector<Byte> read_map_data();
  // other mappings, will want the path to the serialized file and mmap that.
  inline const char* map_file_path() const;
  size_t size() const { return km.size(); }

  const KernelMapping km;
  const bool has_emu_file;
  bool is_sysv_segment;
private:
  std::string map_contents_file;
  size_t read_data_size = 0;
  const char* name;
};

std::vector<DeserializedMapping> read_mappings(const rr::trace::CloneLeader::Reader& task_info_reader, bool* executable_map_found = nullptr);

void map_region_no_file(AutoRemoteSyscalls& remote, const KernelMapping& km);
void map_region_file(AutoRemoteSyscalls& remote, const DeserializedMapping& metadata);
void write_shared_memory_map(ReplayTask* new_task, const KernelMapping& km, std::vector<Byte>&& data);

// re-factor this from `replay_syscall.cc` so that we don't duplicate code like this.
void init_scratch_memory(ReplayTask* t, const KernelMapping& km);

using CapturedMemory = std::vector<std::pair<remote_ptr<void>, std::vector<uint8_t>>>;

} // namespace rr