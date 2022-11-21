/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "CheckpointInfo.h"
#include "GdbCommand.h"

#include "ReplayTask.h"
#include "log.h"

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
  const Checkpoint::Explicit e = gdb_server.timeline.can_add_checkpoint()
                                     ? Checkpoint::EXPLICIT
                                     : Checkpoint::NOT_EXPLICIT;
  gdb_server.checkpoints[checkpoint_id] = Checkpoint(
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
    if (it->second.is_explicit == Checkpoint::EXPLICIT) {
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
           to_string(c.second.mark.get_key().trace_time) + "\t" + c.second.where;
  }
  return out;
}
static SimpleGdbCommand info_checkpoints(
  "info checkpoints",
  "list all checkpoints created with the 'checkpoint' command",
  invoke_info_checkpoints);

string invoke_load_checkpoint(GdbServer& server, Task*, const vector<string>&) {
  auto existing_checkpoints = server.current_session().as_replay()->get_persistent_checkpoints();
  auto cp_deserialized = 0;
  for (const auto& cp : existing_checkpoints) {
    if(server.persistent_checkpoint_is_loaded(cp.unique_id)) {
      continue;
    }
    ScopedFd fd = cp.open_for_read();
    auto session = ReplaySession::create(server.current_session().as_replay()->trace_reader().dir(), server.timeline.current_session().flags());
    int checkpoint_id = ++gNextCheckpointId;
    session->load_checkpoint(cp);

    server.checkpoints[checkpoint_id] = Checkpoint(server.timeline, cp, session);
    cp_deserialized++;
  }
  return "loaded " + std::to_string(cp_deserialized) + " checkpoints from disk";
}

static SimpleGdbCommand load_checkpoint(
  "load-checkpoints",
  "loads persistent checkpoints",
  invoke_load_checkpoint);

string invoke_write_checkpoints(GdbServer& server, Task* t,
                                const vector<string>&) {
  auto new_cps = 0;
  const auto& trace_dir = t->session().as_replay()->trace_reader().dir();
  std::vector<CheckpointInfo> existing_checkpoints;

  for (auto& kvp : server.checkpoints) {
    auto& cp = kvp.second;
    if (!cp.persistent()) {
      if (cp.mark.has_rr_checkpoint()) {
        LOG(debug) << "Checkpoint has clone at " << cp.mark.get_key().trace_time;
        existing_checkpoints.push_back(CheckpointInfo{cp});
        cp.mark.get_checkpoint()->serialize_checkpoint(existing_checkpoints.back());
        new_cps++;
      } else {
        auto mark_with_clone = server.get_timeline().find_closest_mark_with_clone(cp.mark);
        if (!mark_with_clone) {
          std::cout
              << "Could not find a session clone to serialize for checkpoint "
              << kvp.first << '\n';
        } else {
          LOG(debug) << "Current event for checkpoint " << cp.mark.get_key().trace_time
                     << "; closest clone found at event "
                     << mark_with_clone->get_key().trace_time;
          existing_checkpoints.push_back(CheckpointInfo{cp, *mark_with_clone});
          mark_with_clone->get_checkpoint()->serialize_checkpoint(existing_checkpoints.back());
          new_cps++;
        }
      }
    } else {
      // checkpoint has already been serialized.
      existing_checkpoints.emplace_back(cp);
    }
  }

  update_persistent_checkpoint_index(trace_dir, t->arch(), ((ReplayTask*)t)->trace_reader().cpuid_records(), existing_checkpoints);
  return std::to_string(new_cps) + " new checkpoints serialized. (total: " + std::to_string(existing_checkpoints.size()) + ")";
}

static SimpleGdbCommand write_checkpoints(
    "write-checkpoints",
    "make checkpoints persist on disk.",
    invoke_write_checkpoints);

/*static*/ void GdbCommand::init_auto_args() {
  checkpoint.add_auto_arg("rr-where");
}

} // namespace rr
