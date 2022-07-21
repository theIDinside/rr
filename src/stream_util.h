#pragma once
#include "kernel_abi.h"
#include "rr_trace.capnp.h"
#include <string>
#include <capnp/c++.capnp.h>

namespace rr {

class Registers;
class ExtraRegisters;
struct CPUIDRecord;

std::string default_rr_trace_dir();
std::string resolve_trace_name(const std::string& trace_name);
std::string trace_save_dir();
std::string latest_trace_symlink();
// XXX move to trace_utils

capnp::Data::Reader regs_to_raw(const Registers&);
void set_extra_regs_from_raw(SupportedArch arch, const std::vector<CPUIDRecord>& records, capnp::Data::Reader& raw, ExtraRegisters& out);

capnp::Data::Reader extra_regs_to_raw(const ExtraRegisters&);

rr::trace::Arch to_trace_arch(SupportedArch arch);

std::string data_to_str(const kj::ArrayPtr<const capnp::byte>& data);
kj::ArrayPtr<const capnp::byte> str_to_data(const std::string& str);



} // namespace rr
