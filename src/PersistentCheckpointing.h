#pragma once

#include "AddressSpace.h"
#include "ExtraRegisters.h"
#include "Registers.h"
#include "ReplaySession.h"
#include "ReturnAddressList.h"
#include "SerializedCheckpoint.h"
#include "TaskishUid.h"
#include "TraceFrame.h"
#include <sched.h>
namespace rr {

using Byte = std::uint8_t;
using FrameTime = int64_t;

/**
 * Class that reads from /proc/<tid>/mem and writes map contents to file.
 */
class KernelMapWriter {
public:
  KernelMapWriter(Task* task, std::string checkpoint_data_dir);
  ~KernelMapWriter();
  /**
   * Writes the contents of `km` to a file in checkpoints dir of trace. Returns
   * the filename that was written to.
   */
  std::string write_map(const KernelMapping& km) const;
  const char* map_data_dir() const { return checkpoint_directory.c_str(); }
  static std::string file_name_of(const std::string& path);
private:
  int proc_mem_fd;
  pid_t pid;
  std::string checkpoint_directory;
};

class DeserializedMapping {
public:
  DeserializedMapping(const KernelMapping& km, std::string map_contents_filename, bool has_emu);
  Byte* data() const { return (Byte*)data_.data(); }
  Byte* data(size_t offset) const { return data() + offset; }
  size_t size() const { return km.size(); }
  size_t data_written() const { return data_.size(); }
  const KernelMapping km;
  const bool hasEmu;
private:
  std::string map_contents_file;
  int fd;
  std::vector<Byte> data_;
};

using CapturedMemory =
    std::vector<std::pair<remote_ptr<void>, std::vector<uint8_t>>>;

// Deserialize CloneCompletion to `dest.clone_completion` and return
// `SerializedCheckpoint`
SerializedCheckpoint deserialize_clone_completion_into(ReplaySession& dest,
                                                       ScopedFd& fd);

// Write `cloned_session.clone_completion` to `file`.
void serialize_clone_completion(ReplaySession& cloned_session,
                                const std::string& trace_dir,
                                const std::string& file,
                                const SerializedCheckpoint& cp);
} // namespace rr