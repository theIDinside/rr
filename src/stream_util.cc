#include "stream_util.h"
#include <sys/stat.h>

namespace rr {
static bool dir_exists(const string& dir) {
  struct stat dummy;
  return !dir.empty() && stat(dir.c_str(), &dummy) == 0;
}

string latest_trace_symlink() {
  return trace_save_dir() + "/latest-trace";
}

string trace_save_dir() {
  const char* output_dir = getenv("_RR_TRACE_DIR");
  return output_dir ? output_dir : default_rr_trace_dir();
}

string resolve_trace_name(const string& trace_name)
{
  if (trace_name.empty()) {
    return latest_trace_symlink();
  }

  // Single-component paths are looked up first in the current directory, next
  // in the default trace dir.

  if (trace_name.find('/') == string::npos) {
    if (dir_exists(trace_name)) {
      return trace_name;
    }

    string resolved_trace_name = trace_save_dir() + "/" + trace_name;
    if (dir_exists(resolved_trace_name)) {
      return resolved_trace_name;
    }
  }

  return trace_name;
}

string default_rr_trace_dir() {
  static string cached_dir;

  if (!cached_dir.empty()) {
    return cached_dir;
  }

  string dot_dir;
  const char* home = getenv("HOME");
  if (home) {
    dot_dir = string(home) + "/.rr";
  }
  string xdg_dir;
  const char* xdg_data_home = getenv("XDG_DATA_HOME");
  if (xdg_data_home) {
    xdg_dir = string(xdg_data_home) + "/rr";
  } else if (home) {
    xdg_dir = string(home) + "/.local/share/rr";
  }

  // If XDG dir does not exist but ~/.rr does, prefer ~/.rr for backwards
  // compatibility.
  if (dir_exists(xdg_dir)) {
    cached_dir = xdg_dir;
  } else if (dir_exists(dot_dir)) {
    cached_dir = dot_dir;
  } else if (!xdg_dir.empty()) {
    cached_dir = xdg_dir;
  } else {
    cached_dir = "/tmp/rr";
  }

  return cached_dir;
}
} // namespace rr