/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "GdbCommand.h"
#include "EmuFs.h"
#include "GdbServer.h"
#include "PersistentCheckpointing.h"
#include "ReplayTask.h"
#include "ReplayTimeline.h"
#include "ReturnAddressList.h"
#include "ScopedFd.h"
#include "SerializedCheckpoint.h"
#include "log.h"
#include <cstring>
#include <fcntl.h>
#include <string>

using namespace std;

namespace rr {

static SimpleGdbCommand elapsed_time(
    "elapsed-time",
    "Print elapsed time (in seconds) since the start of the trace, in the"
    " 'record' timeline.",
    [](GdbServer&, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return GdbCommandHandler::cmd_end_diversion();
      }

      ReplayTask* replay_t = static_cast<ReplayTask*>(t);
      double elapsed_time = replay_t->current_trace_frame().monotonic_time() -
                            replay_t->session().get_trace_start_time();

      return string("Elapsed Time (s): ") + to_string(elapsed_time);
    });

static SimpleGdbCommand when(
    "when", "Print the current rr event number.",
    [](GdbServer&, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return GdbCommandHandler::cmd_end_diversion();
      }
      return string("Current event: ") +
             to_string(
                 static_cast<ReplayTask*>(t)->current_trace_frame().time());
    });

static SimpleGdbCommand when_ticks(
    "when-ticks", "Print the current rr tick count for the current thread.",
    [](GdbServer&, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return GdbCommandHandler::cmd_end_diversion();
      }
      return string("Current tick: ") + to_string(t->tick_count());
    });

static SimpleGdbCommand when_tid(
    "when-tid", "Print the real tid for the current thread.",
    [](GdbServer&, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return GdbCommandHandler::cmd_end_diversion();
      }
      return string("Current tid: ") + to_string(t->tid);
    });

static std::vector<ReplayTimeline::Mark> back_stack;
static ReplayTimeline::Mark current_history_cp;
static std::vector<ReplayTimeline::Mark> forward_stack;
static SimpleGdbCommand rr_history_push(
    "rr-history-push", "Push an entry into the rr history.",
    [](GdbServer& gdb_server, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        // Don't create new history state inside a diversion
        return string();
      }
      if (current_history_cp) {
        back_stack.push_back(current_history_cp);
      }
      current_history_cp = gdb_server.get_timeline().mark();
      forward_stack.clear();
      return string();
    });
static SimpleGdbCommand back(
    "back", "Go back one entry in the rr history.",
    [](GdbServer& gdb_server, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return GdbCommandHandler::cmd_end_diversion();
      }
      if (back_stack.size() == 0) {
        return string("Can't go back. No more history entries.");
      }
      forward_stack.push_back(current_history_cp);
      current_history_cp = back_stack.back();
      back_stack.pop_back();
      gdb_server.get_timeline().seek_to_mark(current_history_cp);
      return string();
    });
static SimpleGdbCommand forward(
    "forward", "Go forward one entry in the rr history.",
    [](GdbServer& gdb_server, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return GdbCommandHandler::cmd_end_diversion();
      }
      if (forward_stack.size() == 0) {
        return string("Can't go forward. No more history entries.");
      }
      back_stack.push_back(current_history_cp);
      current_history_cp = forward_stack.back();
      forward_stack.pop_back();
      gdb_server.get_timeline().seek_to_mark(current_history_cp);
      return string();
    });

static int gNextCheckpointId = 0;

string invoke_checkpoint(GdbServer& gdb_server, Task*,
                         const vector<string>& args) {
  const string& where = args[1];
  int checkpoint_id = ++gNextCheckpointId;
  GdbServer::Checkpoint::Explicit e;
  if (gdb_server.timeline.can_add_checkpoint()) {
    e = GdbServer::Checkpoint::EXPLICIT;
  } else {
    e = GdbServer::Checkpoint::NOT_EXPLICIT;
  }
  gdb_server.checkpoints[checkpoint_id] = GdbServer::Checkpoint(
      gdb_server.timeline, gdb_server.last_continue_tuid, e, where);
  return string("Checkpoint ") + to_string(checkpoint_id) + " at " + where;
}
static SimpleGdbCommand checkpoint(
  "checkpoint",
  "create a checkpoint representing a point in the execution\n"
  "use the 'restart' command to return to the checkpoint",
  invoke_checkpoint);

string invoke_delete_checkpoint(GdbServer& gdb_server, Task*,
                                const vector<string>& args) {
  int id = stoi(args[1]);
  auto it = gdb_server.checkpoints.find(id);
  if (it != gdb_server.checkpoints.end()) {
    if (it->second.is_explicit == GdbServer::Checkpoint::EXPLICIT) {
      gdb_server.timeline.remove_explicit_checkpoint(it->second.mark);
    }
    gdb_server.checkpoints.erase(it);
    return string("Deleted checkpoint ") + to_string(id) + ".";
  } else {
    return string("No checkpoint number ") + to_string(id) + ".";
  }
}
static SimpleGdbCommand delete_checkpoint(
  "delete checkpoint",
  "remove a checkpoint created with the 'checkpoint' command",
  invoke_delete_checkpoint);

string invoke_info_checkpoints(GdbServer& gdb_server, Task*,
                               const vector<string>&) {
  if (gdb_server.checkpoints.size() == 0) {
    return "No checkpoints.";
  }
  string out = "ID\tWhen\tWhere";
  for (auto& c : gdb_server.checkpoints) {
    out += string("\n") + to_string(c.first) + "\t" +
           to_string(c.second.mark.time()) + "\t" + c.second.where;
  }
  return out;
}
static SimpleGdbCommand info_checkpoints(
  "info checkpoints",
  "list all checkpoints created with the 'checkpoint' command",
  invoke_info_checkpoints);

string invoke_load_checkpoint(GdbServer& server, Task* t, const vector<string>&) {
  const auto& dir = t->session().trace_stream()->dir();
  auto cp_deserialized = 0;
  for(auto i = 1u;;i++) {
    auto len = std::snprintf(nullptr, 0, "%s/checkpoint-%d", dir.c_str(), i);
    char file_path[len+1];
    std::snprintf(file_path, sizeof(file_path), "%s/checkpoint-%d", dir.c_str(), i);
    ScopedFd fd(file_path, O_RDONLY);
    if(fd.get() == -1) break;
    auto session = ReplaySession::create(dir, server.timeline.current_session().flags());
    int checkpoint_id = ++gNextCheckpointId;
    auto serialized_checkpoint = deserialize_clone_completion_into(*session, fd);
    server.checkpoints[checkpoint_id] = GdbServer::Checkpoint(server.timeline, serialized_checkpoint, session);
    cp_deserialized++;
  }
  return std::to_string(cp_deserialized) + " deserialized checkpoints";
}

static SimpleGdbCommand load_checkpoint(
  "load-serialized-checkpoint",
  "deserializes a checkpoint",
  invoke_load_checkpoint);


string invoke_write_checkpoints(GdbServer& server, Task*,
                                const vector<string>& args) {
  if(args.size() < 2) return "You must provide a file name to write serialized data to.";
  auto found_cps = 0;
  for(auto& cp : server.checkpoints) {
    auto ptr = cp.second.mark.get_internal();
    if(ptr && ptr->checkpoint) {
      found_cps++;
      auto fname = ptr->checkpoint->trace_reader().dir() + "/checkpoint-" + std::to_string(found_cps);
      SerializedCheckpoint scp;
      scp.is_explicit = cp.second.is_explicit == GdbServer::Checkpoint::Explicit::EXPLICIT;
      scp.last_continue_tuid = cp.second.last_continue_tuid;
      scp.where = cp.second.where;
      auto& proto = ptr->proto;
      scp.key = MarkKey{.trace_time = proto.key.trace_time, .ticks = proto.key.ticks, .step_key = proto.key.step_key.as_int()};
      scp.regs = cp.second.mark.regs();
      scp.return_addresses = ReturnAddressList(proto.return_addresses);
      scp.extra_regs = cp.second.mark.extra_regs();
      scp.ticks_at_event_start = ptr->ticks_at_event_start;
      scp.singlestep_to_next_mark_no_signal = ptr->singlestep_to_next_mark_no_signal;
      serialize_clone_completion(*ptr->checkpoint, fname, scp);
    }
  }
  return std::to_string(found_cps) + " checkpoints serialized.";
}

static SimpleGdbCommand write_checkpoints(
    "write-checkpoints",
    "Serialize all checkpoints created with the 'checkpoint' command",
    invoke_write_checkpoints);

string invoke_info_written_checkpoints(GdbServer&, Task*,
                                       const vector<string>&) {
  return "test function not implemented";
}

static SimpleGdbCommand info_written_checkpoints(
    "info-written-checkpoints",
    "list all checkpoints written to file by the 'write checkpoints' command",
    invoke_info_written_checkpoints);

/*static*/ void GdbCommand::init_auto_args() {
  checkpoint.add_auto_arg("rr-where");
}

} // namespace rr
