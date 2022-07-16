#pragma once

#include "ExtraRegisters.h"
#include "Registers.h"
#include "ReturnAddressList.h"
#include "TaskishUid.h"
#include "TraceFrame.h"
#include <cstdio>
#include <sstream>

namespace rr {

struct MarkKey {
  FrameTime trace_time;
  Ticks ticks;
  int step_key;
};

struct SerializedCheckpoint {
  bool is_explicit;
  TaskUid last_continue_tuid;
  std::string where;
  MarkKey key;
  Registers regs;
  ReturnAddressList return_addresses;
  ExtraRegisters extra_regs;
  Ticks ticks_at_event_start;
  bool singlestep_to_next_mark_no_signal;

  std::string str() const {
    std::stringstream ss{};
    constexpr auto fmt = "TUID: [serial: %d, tid: %d]\nWHERE: %s\nMARK KEY: [time: "
        "%ld, ticks: %lu]\nTicks at event start: %lu";
    auto len = std::snprintf(nullptr, 0, fmt, last_continue_tuid.serial(), last_continue_tuid.tid(), where.c_str(), key.trace_time, key.ticks, ticks_at_event_start);
    char buffer[len + 1];
    std::snprintf(buffer, sizeof(buffer), fmt, last_continue_tuid.serial(), last_continue_tuid.tid(), where.c_str(), key.trace_time, key.ticks, ticks_at_event_start);
    return buffer;
  }
};
} // namespace rr