#include "stream_util.h"
#include <sys/stat.h>
#include "Registers.h"
#include "ExtraRegisters.h"
#include "util.h"

namespace rr {
static bool dir_exists(const std::string& dir) {
  struct stat dummy;
  return !dir.empty() && stat(dir.c_str(), &dummy) == 0;
}

std::string latest_trace_symlink() {
  return trace_save_dir() + "/latest-trace";
}

std::string trace_save_dir() {
  const char* output_dir = getenv("_RR_TRACE_DIR");
  return output_dir ? output_dir : default_rr_trace_dir();
}

std::string resolve_trace_name(const std::string& trace_name)
{
  if (trace_name.empty()) {
    return latest_trace_symlink();
  }

  // Single-component paths are looked up first in the current directory, next
  // in the default trace dir.

  if (trace_name.find('/') == std::string::npos) {
    if (dir_exists(trace_name)) {
      return trace_name;
    }

    std::string resolved_trace_name = trace_save_dir() + "/" + trace_name;
    if (dir_exists(resolved_trace_name)) {
      return resolved_trace_name;
    }
  }

  return trace_name;
}

std::string default_rr_trace_dir() {
  static std::string cached_dir;

  if (!cached_dir.empty()) {
    return cached_dir;
  }

  std::string dot_dir;
  const char* home = getenv("HOME");
  if (home) {
    dot_dir = std::string(home) + "/.rr";
  }
  std::string xdg_dir;
  const char* xdg_data_home = getenv("XDG_DATA_HOME");
  if (xdg_data_home) {
    xdg_dir = std::string(xdg_data_home) + "/rr";
  } else if (home) {
    xdg_dir = std::string(home) + "/.local/share/rr";
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

trace::Arch to_trace_arch(SupportedArch arch) {
  switch (arch) {
    case x86:
      return trace::Arch::X86;
    case x86_64:
      return trace::Arch::X8664;
    case aarch64:
      return trace::Arch::AARCH64;
    default:
      FATAL() << "Unknown arch";
      return trace::Arch::X86;
  }
}

capnp::Data::Reader regs_to_raw(const Registers& regs) {
  return { regs.get_ptrace_for_self_arch().data, regs.get_ptrace_for_self_arch().size };
}

kj::ArrayPtr<const capnp::byte> str_to_data(const std::string& str) {
  return kj::ArrayPtr<const capnp::byte>(
      reinterpret_cast<const capnp::byte*>(str.data()), str.size());
}

// XXX move to trace_utils
capnp::Data::Reader extra_regs_to_raw(const ExtraRegisters& regs) {
  return { regs.data().data(), regs.data().size() };
};

std::string data_to_str(const kj::ArrayPtr<const capnp::byte>& data) {
  if (memchr(data.begin(), 0, data.size())) {
    FATAL() << "Invalid string: contains null character";
  }
  return std::string(reinterpret_cast<const char*>(data.begin()), data.size());
}

void set_extra_regs_from_raw(SupportedArch arch, const std::vector<CPUIDRecord>& records, capnp::Data::Reader& raw, ExtraRegisters& out) {
  if (raw.size()) {
    ExtraRegisters::Format fmt;
    switch (arch) {
      default:
        FATAL() << "Unknown architecture";
        RR_FALLTHROUGH;
      case x86:
      case x86_64:
        fmt = ExtraRegisters::XSAVE;
        break;
      case aarch64:
        fmt = ExtraRegisters::NT_FPR;
        break;
    }
    auto success = out.set_to_raw_data(arch, fmt, raw.begin(), raw.size(), xsave_layout_from_trace(records));
    if (!success) {
      FATAL() << "Invalid extended register data in trace";
    }
  } else {
    out = ExtraRegisters(arch);
  }
}

} // namespace rr