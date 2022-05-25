#pragma once
#include <string>

namespace rr {
using string = std::string;
string default_rr_trace_dir();
string resolve_trace_name(const string& trace_name);
string trace_save_dir();
string latest_trace_symlink();
} // namespace rr
