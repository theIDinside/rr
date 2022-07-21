# rr capnproto common definitions

@0x8e3dd6999106d5e8

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("rr::trace");

# We generally use Data instead of Text because for e.g. files there is no
# guarantee the data are valid UTF-8.
# We use the natural system types whenever possible. For example, even though
# negative fds are not possible, we use Int32 for fds to match kernel/library
# APIs. This avoids potential problems where the trace value doesn't fit into
# the range of the type where it is actually used.
# "Must" constraints noted below should be checked by consumers.

# A path that could be used during replay.
# Must not contain any null bytes
using Path = Data;

# Must not contain any null bytes
using CString = Data;

using Device = UInt64;
using Inode = UInt64;
using RemotePtr = UInt64;

# Must be > 0
using FrameTime = Int64;
# Must be > 0
using Tid = Int32;
# Must be >= 0
using Ticks = Int64;
# Must be >= 0
using Fd = Int32;

using Pid = Int32;

# A file descriptor belonging to a task
struct RemoteFd {
  tid @0 :Tid;
  fd @1 :Int32;
}