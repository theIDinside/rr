# rr ReplaySession schema

@0xf55676ebd869d6c1;

using Cxx = import "/capnp/c++.capnp";

using import "rr_trace.capnp".Registers;
using import "rr_trace.capnp".ExtraRegisters;
using import "rr_trace.capnp".Arch;
using import "rr_trace.capnp".RemoteFd;

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

using StreamBufferOffset = UInt64;

# Key by which to look up shared data. First iteration is basically
# (uintptr_t)foo where foo is a pointer of type T
using Reference = UInt64;

struct ReadersPosition {
  events    @0 :StreamBufferOffset;
  rawData   @1 :StreamBufferOffset;
  mmaps     @2 :StreamBufferOffset;
  tasks     @3 :StreamBufferOffset;
}

enum ReplayTraceStepType {
  none @0;
  enterSyscall @1;
  exitSyscall @2;
  deterministicSignal @3;
  programAsyncSignalInterrupt @4;
  deliverSignal @5;
  flushSyscallbuf @6;
  patchSyscall @7;
  patchAfterSyscall @8;
  patchVsyscall @9;
  exitTask @10;
  retire @11;
}

struct MarkKey {
    traceTime @0 :FrameTime;
    ticks @1 :Ticks;
    stepKey @2 :Int32;
}

struct ProtoMark {
  key @0 :MarkKey;
  regs @1: Registers;
  returnAddresses @2 :List(RemotePtr); # Maybe use :Data here and just cast it on rebuild
}

# GdbServer::Checkpoint
struct Checkpoint {
  explicit @0 :Bool;
  lastContinueTuid :group {
    pid @1 :Pid;
    serial @2 :UInt32;
  }
  where @3 :Data;
  # InternalMark
  # Protomark
  proto @4 :ProtoMark;
  # InternalMark continue
  extraRegs @5: ExtraRegisters;
  ticksAtEventStart @6 :Ticks;
  singlestepToNextMarkNoSignal @7 :Bool;
}

enum MappedDataSource {
  trace @0;
  file @1;
  zero @2;
}

struct KernelMapping {
  start       @0:RemotePtr;
  end         @1:RemotePtr;
  fsname      @2:CString;
  device      @3:Device;
  inode       @4:Inode;
  protection  @5:Int32;
  flags       @6:Int32;
  offset      @7:UInt64;
  # mappedData :group {
  #   time            @8:FrameTime;
  #   source          @9:MappedDataSource;
  #   fileName        @10:Data;
  # }
  contents    @8:Data;    # Warning. Could potentially be massive.
  # extraFds @9 :List(RemoteFd);
  # True if the mapped fd was read-only and should not be monitored
  skipMonitoringMappedFd @9 :Bool;
  rrSysMap @10 :Int8;
  hasEmuFile @11 :Bool;
}

struct InitBufferParams {
  deschedCounterFd @0 :Fd;
  clonedFileDataFd @1 :Fd;
  syscallBufPtr @2 :UInt64;
  scratchBuffer @3 :UInt64;
  usableScratchSize @4 :UInt64;
}

# Task Info for clone leader. Should have an exe base ?
struct TaskInfo {
  tid @0 :Tid;
  recTid @1 :Tid;
  serial @2 :UInt32;
  arch @3 :Arch;
  memoryMappings @4 :List(KernelMapping); # offsets into mmaps substream where this tasks KernelMappings are found.
  exeBase @5 :RemotePtr;
  registers @6 :Registers;
  extraRegisters @7 :ExtraRegisters;
  executableFileName @8 :Data;
  initBufferParams @9 :InitBufferParams;
  clonedFileDataFName @10 :Data;
}

struct CapturedState {
  ticks @0 :Ticks;
  regs @1 :Registers;
  extraRegs @2 :ExtraRegisters;
  prname @3 :Data;
  fdtableIdentity @4 :UInt64;
  syscallbufChild @5 :RemotePtr;
  syscallbufSize @6 :UInt64;
  numSyscallbufBytes @7 :UInt64;
  preloadGlobals @8 :RemotePtr;
  scratchPtr @9 :RemotePtr;
  scratchSize @10 :UInt64;
  topOfStack @11 :RemotePtr;
  rseqState :group {
    ptr @12 :RemotePtr;
    abortPrefixSignature @13 :UInt32;
  }
  clonedFileDataOffset @14 :UInt64;
  threadLocals @15 :Data;
  recTid @16 :Pid;
  ownNamespaceRecTid @17 :Pid;
  serial @18 :UInt32;
  tguid :group {
    tid @19 :Pid;
    serial @20 :UInt32;
  }
  deschedFdChild @21 :Int32;
  clonedFileDataFdChild @22 :Int32;
  clonedFileDataFname @23 :Data;
  waitStatus @24 :Int32;
  tlsRegister @25 :UInt64;
  threadAreas @26 :List(Data); # std::vector<X86Arch::user_desc>
}

struct CapturedMemory {
  startAddress @0 :RemotePtr;
  data @1 :Data;
}

struct AddressSpaceClone {
  cloneLeader @0 :TaskInfo;
  cloneLeaderState @1 :CapturedState;
  memberState @2 :List(CapturedState);
  capturedMemory @3 :List(CapturedMemory);
}

struct CloneCompletionInfo {
  addressSpaces @0 :List(AddressSpaceClone);
  # the checkpoint in ReplayTimeline
  checkpoint @1: Checkpoint;
  sessionCurrentStep @2: Data;
}