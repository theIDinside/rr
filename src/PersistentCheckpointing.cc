#include "PersistentCheckpointing.h"
#include "rr_replay_session.capnp.h"
#include "EmuFs.h"
#include "Session.h"
#include "TraceFrame.h"
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <cstdint>

namespace rr {

void deserialize(ReplaySession& dest, int /* fd */) {
  DEBUG_ASSERT(dest.clone_completion == nullptr);
}

void serialize_clone_completion(ReplaySession& cloned_session) {
  DEBUG_ASSERT(cloned_session.clone_completion != nullptr);
}
} // namespace rr