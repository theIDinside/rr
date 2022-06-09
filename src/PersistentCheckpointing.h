#pragma once

#include "ReplaySession.h"
namespace rr {

  // Write CloneCompletion to `dest.clone_completion`
  void deserialize(ReplaySession& dest, int fd);

  // Write `cloned_session.clone_completion` to file.
  void serialize_clone_completion(ReplaySession& cloned_session);
} // namespace rr