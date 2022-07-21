# rr ReplaySession schema

@0xf55676ebd869d6c1;

using Cxx = import "/capnp/c++.capnp";

using import "rr_trace.capnp".Registers;
using import "rr_trace.capnp".ExtraRegisters;
using import "rr_trace.capnp".Arch;
using import "rr_trace.capnp".RemoteFd;
using import "rr_trace.capnp".CString;
using import "rr_trace.capnp".Device;
using import "rr_trace.capnp".Inode;
using import "rr_trace.capnp".RemotePtr;
using import "rr_trace.capnp".FrameTime;
using import "rr_trace.capnp".Tid;
using import "rr_trace.capnp".Fd;
using import "rr_trace.capnp".Path;
using import "rr_trace.capnp".Ticks;

$Cxx.namespace("rr::trace");

using Pid = Tid;
using FileMonitorType = Int32;
struct FileMonitor {
  fd @0 :Fd;
  type @1 :FileMonitorType;
  union {
    mmap :group {
      dead @2 :Bool;
      device @3 :Device;
      inode @4 :Inode;
    }
    procFd :group {
      pid @5 :Pid;
      serial @6 :UInt32;
    }
    procMem :group {
      pid @7 :Pid;
      serial @8 :UInt32;
      execCount @9 :UInt32;
    }
    stdio @10 :Fd;
    procStat @11 :Data;
    bpf :group {
      keySize @12: UInt64;
      valueSize @13 :UInt64;
    }
  }
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
  # extraFds @9 :List(RemoteFd);
  # True if the mapped fd was read-only and should not be monitored
  mapType :union {
    file :group { # mapping of a file
      skipMonitoringMappedFd @8 :Bool; # unsure if needed, or how it's used
      contentsPath @9 :Path;
    }
    guardSegment @10 :Void; # Empty map segment, PROT NONE, no pages in memory, no fsname. Maybe misnomer for this?
    sharedAnon :group {
      skipMonitoringMappedFd @11 :Bool; # unsure if needed, or how it's used
      contentsPath @12 :Path;
      isSysVSegment @13 :Bool; # if we're a SysV, we need to set AddressSpace::shm_sizes[start] = size;
    }
    privateAnon :group { # for instance, stack, heap, so on
      contentsPath @14 :Path;
    }
  }
}

# For coming syscall buffer compatibility.
struct InitBufferParams {
  deschedCounterFd @0 :Fd;
  clonedFileDataFd @1 :Fd;
  syscallBufPtr @2 :UInt64;
  scratchBuffer @3 :UInt64;
  usableScratchSize @4 :UInt64;
}

# Task metadata for clone leader.
struct CloneLeader {
  tid @0 :Tid;
  recTid @1 :Tid;
  serial @2 :UInt32;
  arch @3 :Arch;
  # Clone leader Virtual Address Space
  virtualAddressSpace @4 :List(KernelMapping);
  exeBase @5 :RemotePtr;
  registers @6 :Registers;
  extraRegisters @7 :ExtraRegisters;
  exe @8 :Data;
  initBufferParams @9 :InitBufferParams;
  clonedFileDataFName @10 :Data;
  monitors @11 :List(FileMonitor);
  taskFirstRunEvent @12 :FrameTime;
  vmFirstRunEvent @13   :FrameTime;
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
  cloneLeader @0 :CloneLeader;
  cloneLeaderState @1 :CapturedState;
  memberState @2 :List(CapturedState);
  capturedMemory @3 :List(CapturedMemory);
  auxv @4 :Data;
}

struct CloneCompletionInfo {
  addressSpaces @0 :List(AddressSpaceClone);
  sessionCurrentStep @1: Data;
  lastSigInfo @2 :Data;
}


# Information about an explicit "GDB Checkpoint"
struct CheckpointInfo {
  # points to CloneCompletionInfo header file (represented by CheckpointInfo::info_file)
  cloneCompletionFile @0 :Path;
  time @1 :FrameTime;
  id @2 :UInt64;
  lastContinueTuid :group {
    pid @3 :Pid;
    serial @4 :UInt32;
  }
  where @5 :Data;
  # InternalMark
  # Protomark
  regs @6: Registers;
  returnAddresses @7 :List(RemotePtr); # XXX(simon): Maybe use :Data here and just cast it on rebuild
  ticks @8 :Ticks;
  stepKey @9 :Int32;
  # InternalMark continue
  extraRegs @10: ExtraRegisters;
  ticksAtEventStart @11 :Ticks;
  singlestepToNextMarkNoSignal @12 :Bool;
}

# The checkpoint index file
struct PersistentCheckpoints {
  checkpoints @0 :List(CheckpointInfo);
}