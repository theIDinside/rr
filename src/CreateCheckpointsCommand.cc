#include "CheckpointInfo.h"
#include "Command.h"
#include "CreateCheckpointsCommand.h"
#include "ReplayTimeline.h"
#include "TraceStream.h"
#include "log.h"
#include "main.h"
#include <cstdint>

namespace rr {

CreateCheckpointsCommand CreateCheckpointsCommand::singleton(
    "create-checkpoints", " rr create-checkpoints [OPTION]... [<trace_dir>]\n"
                          "  -i, --interval=<N>        Create persistent checkpoints on an interval of <N>\n"
                          "                            events.\n"
                          "  -s, --start=<N>           Start setting checkpoints at event <N>\n"
                          "  -e, --end=<N>             Stop setting checkpoints at event <N>\n"
                          "\n"
                          "Creates a checkpoint at an interval of N events. "
                          "The command will attempt to\n"
                          "honor this interval as closely as possible.\n");

static bool parse_options(std::vector<std::string>& args,
                          CreateCheckpointsFlags& options) {
  if (parse_global_option(args)) {
    return true;
  }
  static const OptionSpec op_spec[] = {
    { 'i', "--interval", HAS_PARAMETER },
    { 's', "--start", HAS_PARAMETER },
    { 'e', "--end", HAS_PARAMETER }
  };

  ParsedOption opt;
  if (!Command::parse_option(args, op_spec, &opt)) {
    return false;
  }
  switch (opt.short_name) {
    case 'i':
      options.events_interval = static_cast<uint64_t>(std::abs(opt.int_value));
      break;
    case 's':
      options.start_event = static_cast<uint64_t>(std::abs(opt.int_value));
    break;
    case 'e':
      options.end_event = static_cast<uint64_t>(std::abs(opt.int_value));
    break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
      return false;
  }
  return true;
}

bool CreateCheckpointsCommand::verify_params_ok(const CreateCheckpointsFlags& flags) {
  if (flags.events_interval == 0) {
    std::cout << "You need to provide an interval to set checkpoints at.\n";
    return false;
  }
  if(flags.end_event < flags.start_event) {
    std::cout << "start & end has invalid values";
    return false;
  }
  if((flags.end_event == UINT64_MAX && flags.start_event == 0) || (flags.start_event != 0 && flags.end_event == UINT64_MAX)) {
    return true;
  }

  if((flags.end_event - flags.start_event) < flags.events_interval) {
    std::cout << "interval too large, can't fit between start & end";
    return false;
  }
  return true;
}

int CreateCheckpointsCommand::run(std::vector<std::string>& args) {
  CreateCheckpointsFlags flags;
  bool found_dir = false;
  std::string trace_dir{};
  while (!args.empty()) {
    if (parse_options(args, flags)) {
      continue;
    }
    if (!found_dir && parse_optional_trace_dir(args, &trace_dir)) {
      found_dir = true;
      continue;
    }
    print_help(stderr);
    return 1;
  }

  if(!verify_params_ok(flags)) {
    print_help(stderr);
    return 1;
  }

  auto verified_frames_to_checkpoint_at =
      CreateCheckpointsCommand::find_events_to_checkpoint(trace_dir, flags);
  if (verified_frames_to_checkpoint_at.empty()) {
    std::cout << "No checkpointable events found.\n";
    return 2;
  }
  return run_main(trace_dir, verified_frames_to_checkpoint_at);
}

int CreateCheckpointsCommand::run_main(const std::string& trace_dir, const std::vector<FrameTime>& verified_events) {
  DEBUG_ASSERT(!verified_events.empty() &&
               "No events provided to checkpoint at.");
  ReplaySession::Flags session_flags{};
  ReplayTimeline timeline{ ReplaySession::create(trace_dir, session_flags) };
  std::vector<CheckpointInfo> cp_infos;
  auto& reader = timeline.current_session().trace_reader();
  for (const auto evt : verified_events) {
    RunCommand cmd = RUN_CONTINUE;
    while (reader.time() < evt) {
      auto r = timeline.replay_step_forward(cmd, evt);
    }
    auto& session = timeline.current_session();
    if (session.trace_reader().time() == evt) {
      ASSERT(session.current_task(),
             session.can_clone())
          << "could not clone at frame " << evt;
      auto mark = timeline.add_explicit_checkpoint();
      CheckpointInfo cp_info{ session.current_task()->tuid(), mark };
      cp_infos.push_back(cp_info);
      mark.get_checkpoint()->serialize_checkpoint(cp_info);
      timeline.remove_explicit_checkpoint(mark);
      LOG(debug) << "Serialized checkpoint at event " << evt;
    } else {
      FATAL() << "Stopped at wrong event";
    }
  }

  update_persistent_checkpoint_index(
      timeline.current_session().trace_reader().dir(),
      timeline.current_session().arch(),
      timeline.current_session().trace_reader().cpuid_records(), cp_infos);
  std::cout << "Create checkpoints run successfully finished: "
            << cp_infos.size() << " checkpoints created." << std::endl;
  return 0;
}

std::vector<FrameTime> CreateCheckpointsCommand::find_events_to_checkpoint(const std::string& trace_dir, const CreateCheckpointsFlags& flags) {
  TraceReader reader{ trace_dir };
  std::vector<FrameTime> events;
  auto total = 0ul;
  if(flags.start_event != 0) {
    while(!reader.at_end()) {
      total++;
      const auto f = reader.read_frame();
      if(f.time() >= static_cast<long>(flags.start_event) && f.event().can_checkpoint_at()) {
        events.push_back(f.time());
        break;
      }
    }
    if(reader.at_end()) {
      std::cout << "Trace is shorter than " << flags.start_event
                << " (total trace events: " << total << ")"
                << "Aborting." << std::endl;
      return {};
    }
  }

  while (!reader.at_end() && total <= flags.end_event) {
    const auto f = reader.read_frame();
    auto next = (events.size() + 1) * flags.events_interval + flags.start_event;
    if (f.time() >= static_cast<long>(next) && f.event().can_checkpoint_at()) {
      LOG(debug) << "event to checkpoint at: " << f.event() << " at time "
                 << f.time();
      events.push_back(f.time());
    }
    total++;
  }
  return events;
}

}; // namespace rr