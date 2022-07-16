#pragma once

#include "ExtraRegisters.h"
#include "Registers.h"
#include "ReplaySession.h"
#include "ReturnAddressList.h"
#include "SerializedCheckpoint.h"
#include "TaskishUid.h"
#include "TraceFrame.h"
namespace rr {

  using CapturedMemory = std::vector<std::pair<remote_ptr<void>, std::vector<uint8_t>>>;
  // Write CloneCompletion to `dest.clone_completion`
  SerializedCheckpoint deserialize_clone_completion_into(ReplaySession& dest, ScopedFd& fd);
  // Write `cloned_session.clone_completion` to file.
  void serialize_clone_completion(ReplaySession& cloned_session, const std::string& file, const SerializedCheckpoint& cp);
} // namespace rr