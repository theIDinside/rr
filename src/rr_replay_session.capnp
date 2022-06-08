# rr ReplaySession schema

@0xf55676ebd869d6c1;

using Cxx = import "/capnp/c++.capnp";

using import "rr_trace.capnp".Registers;
using import "rr_trace.capnp".ExtraRegisters;
using import "rr_trace.capnp".TicksSemantics;

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

# Key by which to look up shared data. First iteration is basically
# (uintptr_t)foo where foo is a pointer of type T
using Reference = UInt64;

struct KernelMapping {
  mapping @0 :MemoryRange;
  fsname @1 :Data;
  device @2 :Device;
  inode @3 :Inode;
  prot @4 :Int32;
  flags @5 :Int32;
  offset @6 :UInt64;
}

struct ReplaySession {
  ticksAtStartOfEvent @0 :Ticks;
}

struct SysCallBuffer {
  buffer @0 :Data;
}

# ThreadGroup : HasTaskSet
struct ThreadGroup {
  tasks @0 :List(Reference);
  tgid @1 :Pid;
  tgidOwnNamespace @2 :Pid;
  exitStatus @3 :Int32;
  dumpable @4 :Bool;
  execed @5 :Bool;
  receivedSigframeSIGSEGV @6 :Bool;
  parent @7 :Reference; # ThreadGroup *
  children @8 :List(Reference); # std::set<ThreadGroup*>
  firstRunEvent @9 :FrameTime;
  serial @10 :UInt32;

  selfReferenceValue @11 :Reference;
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
  threadAreas @26 :Data; # std::vector<X86Arch::user_desc>
}

struct MemoryRange {
  start @0 :RemotePtr;
  end @1 :RemotePtr;
}

struct EmuFile {
  origPath  @0 :Data;
  tmpPath   @1 :Data;
  file      @2 :Fd;
  owner     @3 :Reference; # When deserializing, we create an EmuFs for each different owner we come across, and then we add the EmuFile's to that.
  size      @4 :UInt64;
  device    @5 :Device;
  inode     @6 :Inode;
}

struct Mapping {
  map @0 :KernelMapping;
  recordedMap @1 :KernelMapping;
  emuFile @2 :Reference; # Reference to EmuFile
  mappedFileState @3 :Data; # std::unique_ptr<struct stat>
  localAddress @4 :Reference; # uint8_t* represented as uintptr_t, which keys to meta data for a memory mapping, so it will be resolved at de-serialize time
  monitoredSharedMemory @5 :Reference; # Reference to MonitoredSharedMemory, via a shared_ptr
  flags @6 :UInt32;
}

struct MemoryMapping {
  memoryRange @0 :MemoryRange;
  mapping @1 :Mapping;
}

struct ShmSegmentSize {
  address @0 :RemotePtr;
  size @1 :UInt64;
}

struct VMem {
  start @0 :RemotePtr;
  end @1 :RemotePtr;
  data @2 :Data;
}

# AddressSpace : HasTaskSet
struct AddressSpace {
  breakpoints @0:Int32; # Change this to something better later on
  exe @1 :Data;
  leaderTid @2 :Pid;
  leaderSerial @3 :UInt32;
  execCount @4 :UInt32;
  brkStart @5 :RemotePtr;
  brkEnd @6 :RemotePtr;
  mem @7 :MemoryMapping;
  shmSizes @8 :List(ShmSegmentSize);
  monitoredMem @9 :List(RemotePtr);
  dontFork @10 :List(MemoryRange);
  wipeOnFork @11 :List(MemoryRange);
  threadLocalsTuid :group {
    pid @12 :Pid;
    serial @13 :UInt32;
  }
  vdsoStartAddr @14 :RemotePtr;
  watchpoints @15 :Int32; # WatchPointMap
  savedWatchpoints @16 :Int32; # :List(WatchPointMap);
  childMemFd @17 :Fd;
  tracedSyscalIp @18 :RemotePtr;
  privilegedTracedSyscallIp @19 :RemotePtr;
  sycallbufEnabled @20 :Bool;
  doBreakpointFaultAddr @21 :RemotePtr;
  stoppingBreakpointTable @22 :RemotePtr;
  stoppingBreakpointTableEntrySize @23 :Int32;
  savedAuxv @24 :Data;
  savedInterpreterBase @25 :RemotePtr;
  savedLdPath @26 :Data;
  firstRunEvent @27 :FrameTime;
  stapSemaphores @28 :List(RemotePtr);
  prname @29 :Data;
  tasks @30 :List(Reference);
}

struct FdTable {
  fds @0 :List(Fd); # list of fd that gets translated to FileMonitors (Whatever that is)
  fdCountBeyondLimit @1 :Int32;
  tasks @2 :List(Reference); # std::set<Task*>
}

enum TrappedInstruction {
  none @0;
  rdtsc @1;
  rdtscp @2;
  cpuid @3;
  int3 @4;
  pushf @5;
  pushf16 @6;
}

using ResumeRequest = Int32;

struct PerfCounters {
  countingPeriod @0 :Ticks;
  tid @1 :Tid;
  pmuIndex @2 :Int32;
  fdTicksMeasure @3 :Fd;
  fdMinusTicksMeasure @4 :Fd;
  fdTicksInterrupt @5 :Fd;
  fdUselessCounter @6 :Fd;
  fdTicksInTransaction @7 :Fd;
  fdStretchCounter @8: Fd;
  ticksSemantics @9 :TicksSemantics;
  start @10 :Bool;
  counting @11 :Bool;
}

struct Task {
  scratchPtr @0 :RemotePtr;
  scratchSize @1 :UInt64;
  deschedFdChild @2 :Fd;
  clonedFileDataFdChild @3 :Fd;
  clonedFileDataFname @4 :Data;
  rseqState :group {
    ptr @5 :RemotePtr;
    abortPrefixSignature @6 :UInt32;
  }
  hpc @7 :PerfCounters;
  tid @8 :Pid;
  recTid @9 :Pid;
  ownNamespaceRecTid @10 :Pid;
  syscallbufSize @11 :UInt64;
  syscallbufChild @12 :RemotePtr;
  preloadGlobals @13 :RemotePtr;
  threadLocals @14 :Data;
  # protected
  serial @15 :UInt32;
  as @16 :AddressSpace;
  fds @17 :FdTable;
  prname @18 :Data;
  ticks @19 :Ticks;
  registers @20 :Registers;
  addressOfLastExecutionResume @21 :RemotePtr;
  howLastExecutionResumed @22 :ResumeRequest;
  lastResumeOrigCx @23 :UInt64;
  singlesteppingInstruction @24 :TrappedInstruction;
  didSetBreakpointAfterCpuid @25 :Bool;
  isStopped @26 :Bool;
  seccompBpfEnabled @27 :Bool;
  detectedUnexpectedExit @28 :Bool;
  registersDirty @29 :Bool;
  origSyscallnoDirty @30 :Bool;
  extraRegisters @31 :ExtraRegisters;
  extraRegistersKnown @32 :Bool;
  tg @33 :ThreadGroup;
  threadAreas @34 :List(Data);
  topOfStack @35 :RemotePtr;
  waitStatus @36 :Int32;
  pendingSiginfo @37 :Data;
  seenPtraceExitEvent @38 :Bool;
  handledPtraceExitEvent @39 :Bool;
  expectingPtraceInterruptStop @40 :Int32;
  wasReaped @41 :Bool;
  forgotten @42 :Bool;

  selfReferenceValue @43 :Reference; # Identifier we use for this task. It is the equivalent of (uintptr_t)this
}

# represents the key value pair in std::map<uintptr_t, FdTable::shr_ptr>
struct ClonedFd {
  ptr @0 :UInt64;
  fdTablePtr @1 :FdTable;
  taskSet @2 :List(Reference); # std::set<Task*>
}

using ClonedFdTables = List(ClonedFd);

struct CapturedMemory {
  ptr @0 :RemotePtr;
  buf @1 :Data;
}

struct AddressSpaceClone {
  cloneLeader @0 :Reference;            # Task*
  cloneLeaderState @1 :CapturedState;
  memberStates @2 :List(CapturedState);
  capturedMemory @3 :List(CapturedMemory);
}

struct CloneCompletion {
  addressSpaces @0 :List(AddressSpaceClone);
  clonedFdTables @1 :ClonedFdTables;

  tasksData @2 :List(Task);
  threadGroupsData @3 :List(ThreadGroup);
  addressSpaceData @4 :List(AddressSpace);
}