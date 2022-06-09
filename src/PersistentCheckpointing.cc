#include "PersistentCheckpointing.h"
#include "rr_replay_session.capnp.h"
#include "EmuFs.h"
#include "Session.h"
#include "TraceFrame.h"
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <cstdint>

namespace rr {

void deserialize(ReplaySession& dest, int fd) {
  DEBUG_ASSERT(dest.clone_completion == nullptr);
  std::map<uintptr_t, Task*> task_data;
  std::map<uintptr_t, ThreadGroup*> thread_group_data;
  std::map<uintptr_t, AddressSpace*> address_space_data;
  // Steps to deserializing; all members of types that are pointers or references to data;
  ::capnp::PackedFdMessageReader message(fd);
  auto cc_reader = message.getRoot<trace::CloneCompletion>();
  auto streamDataPosition = cc_reader.getReadersPosition();
  for(auto& as_space : cc_reader.getAddressSpaces()) {
    auto cs = as_space.getCloneLeaderState();
  }
}

void serialize_clone_completion(ReplaySession& cloned_session) {
  DEBUG_ASSERT(cloned_session.clone_completion != nullptr);
  ::capnp::MallocMessageBuilder message;
  trace::CloneCompletion::Builder cc = message.initRoot<trace::CloneCompletion>();
  auto count = cloned_session.clone_completion->address_spaces.size();

  for(auto i = 0u; i < count; i++) {

  }

}
} // namespace rr