#pragma once

#include "AddressSpace.h"
#include "CheckpointInfo.h"
#include "log.h"
#include "rr_pcp.capnp.h"
#include <capnp/blob.h>
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <kj/common.h>
namespace rr {

using Byte = std::uint8_t;
using FrameTime = int64_t;

// Persistent checkpointing related utilities

void write_capture_state(trace::CapturedState::Builder& ms,
                         const Task::CapturedState& state);

/**
 * Writes the VM of |clone_leader| using the Capnproto |builder|. Checkpoint
 * specific data, like the serialized segments are stored in
 * |checkpoint_data_dir|
 */
void write_vm(Task* clone_leader, rr::trace::CloneLeader::Builder builder,
              const std::string& checkpoint_data_dir);

/**
 * Write file |monitor| information to capnproto |builder|
 */
void write_monitor(rr::trace::FileMonitor::Builder& builder, int fd,
                   FileMonitor* monitor);

/**
 * Restores Task::CapturedState from capnproto data.
 */
Task::CapturedState reconstitute_captured_state(
    ReplaySession& s, trace::CapturedState::Reader reader);

void map_private_anonymous(AutoRemoteSyscalls& remote, const KernelMapping& km);

/**
 * Maps a file-backed (read only) segment in `remote.task()`.
 */
void map_region_file(AutoRemoteSyscalls& remote, const KernelMapping& km,
                     const std::string& file_path);

// XXX re-factor this from `replay_syscall.cc` so that we don't duplicate code
// like this. It's identical, but without assertion. Need input from maintainers
// on where to put this.
void init_scratch_memory(ReplayTask* t, const KernelMapping& km);

using CapturedMemory =
    std::vector<std::pair<remote_ptr<void>, std::vector<uint8_t>>>;

} // namespace rr