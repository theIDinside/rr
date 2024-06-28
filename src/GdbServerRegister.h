/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_SERVER_REGISTER_H_
#define RR_GDB_SERVER_REGISTER_H_

namespace rr {

/**
 * This is the register numbering used by GDB.
 */
enum GdbServerRegister {
  DREG_EAX,
  DREG_ECX,
  DREG_EDX,
  DREG_EBX,
  DREG_ESP,
  DREG_EBP,
  DREG_ESI,
  DREG_EDI,
  DREG_EIP,
  DREG_EFLAGS,
  DREG_CS,
  DREG_SS,
  DREG_DS,
  DREG_ES,
  DREG_FS,
  DREG_GS,
  DREG_FIRST_FXSAVE_REG,
  DREG_ST0 = DREG_FIRST_FXSAVE_REG,
  DREG_ST1,
  DREG_ST2,
  DREG_ST3,
  DREG_ST4,
  DREG_ST5,
  DREG_ST6,
  DREG_ST7,
  // These are the names GDB gives the registers.
  DREG_FCTRL,
  DREG_FSTAT,
  DREG_FTAG,
  DREG_FISEG,
  DREG_FIOFF,
  DREG_FOSEG,
  DREG_FOOFF,
  DREG_FOP,
  DREG_XMM0,
  DREG_XMM1,
  DREG_XMM2,
  DREG_XMM3,
  DREG_XMM4,
  DREG_XMM5,
  DREG_XMM6,
  DREG_XMM7,
  DREG_MXCSR,
  // XXX the last fxsave reg on *x86*
  DREG_LAST_FXSAVE_REG = DREG_MXCSR,
  DREG_ORIG_EAX,
  DREG_YMM0H,
  DREG_YMM1H,
  DREG_YMM2H,
  DREG_YMM3H,
  DREG_YMM4H,
  DREG_YMM5H,
  DREG_YMM6H,
  DREG_YMM7H,
  DREG_PKRU,
  DREG_NUM_LINUX_I386,
  // Last register we can find in user_regs_struct
  // (except for orig_eax).
  DREG_NUM_USER_REGS = DREG_GS + 1,

  // x86-64 register numbers
  DREG_RAX = 0,
  DREG_RBX,
  DREG_RCX,
  DREG_RDX,
  DREG_RSI,
  DREG_RDI,
  DREG_RBP,
  DREG_RSP,
  DREG_R8,
  DREG_R9,
  DREG_R10,
  DREG_R11,
  DREG_R12,
  DREG_R13,
  DREG_R14,
  DREG_R15,
  DREG_RIP,
  // Things get a little tricky here, because x86-64 has some registers
  // named identically to its x86 counterpart, but we've used the names
  // in the x86 register definitions above, and the numbers they need
  // to represent are different.  Hence the unique names here.
  DREG_64_EFLAGS,
  DREG_64_CS,
  DREG_64_SS,
  DREG_64_DS,
  DREG_64_ES,
  DREG_64_FS,
  DREG_64_GS,
  DREG_64_FIRST_FXSAVE_REG,
  DREG_64_ST0 = DREG_64_FIRST_FXSAVE_REG,
  DREG_64_ST1,
  DREG_64_ST2,
  DREG_64_ST3,
  DREG_64_ST4,
  DREG_64_ST5,
  DREG_64_ST6,
  DREG_64_ST7,
  // These are the names GDB gives the registers.
  DREG_64_FCTRL,
  DREG_64_FSTAT,
  DREG_64_FTAG,
  DREG_64_FISEG,
  DREG_64_FIOFF,
  DREG_64_FOSEG,
  DREG_64_FOOFF,
  DREG_64_FOP,
  DREG_64_XMM0,
  DREG_64_XMM1,
  DREG_64_XMM2,
  DREG_64_XMM3,
  DREG_64_XMM4,
  DREG_64_XMM5,
  DREG_64_XMM6,
  DREG_64_XMM7,
  DREG_64_XMM8,
  DREG_64_XMM9,
  DREG_64_XMM10,
  DREG_64_XMM11,
  DREG_64_XMM12,
  DREG_64_XMM13,
  DREG_64_XMM14,
  DREG_64_XMM15,
  DREG_64_MXCSR,
  DREG_64_LAST_FXSAVE_REG = DREG_64_MXCSR,
  DREG_ORIG_RAX,
  DREG_FS_BASE,
  DREG_GS_BASE,
  DREG_64_YMM0H,
  DREG_64_YMM1H,
  DREG_64_YMM2H,
  DREG_64_YMM3H,
  DREG_64_YMM4H,
  DREG_64_YMM5H,
  DREG_64_YMM6H,
  DREG_64_YMM7H,
  DREG_64_YMM8H,
  DREG_64_YMM9H,
  DREG_64_YMM10H,
  DREG_64_YMM11H,
  DREG_64_YMM12H,
  DREG_64_YMM13H,
  DREG_64_YMM14H,
  DREG_64_YMM15H,
  DREG_64_XMM16,
  DREG_64_XMM17,
  DREG_64_XMM18,
  DREG_64_XMM19,
  DREG_64_XMM20,
  DREG_64_XMM21,
  DREG_64_XMM22,
  DREG_64_XMM23,
  DREG_64_XMM24,
  DREG_64_XMM25,
  DREG_64_XMM26,
  DREG_64_XMM27,
  DREG_64_XMM28,
  DREG_64_XMM29,
  DREG_64_XMM30,
  DREG_64_XMM31,
  DREG_64_YMM16H,
  DREG_64_YMM17H,
  DREG_64_YMM18H,
  DREG_64_YMM19H,
  DREG_64_YMM20H,
  DREG_64_YMM21H,
  DREG_64_YMM22H,
  DREG_64_YMM23H,
  DREG_64_YMM24H,
  DREG_64_YMM25H,
  DREG_64_YMM26H,
  DREG_64_YMM27H,
  DREG_64_YMM28H,
  DREG_64_YMM29H,
  DREG_64_YMM30H,
  DREG_64_YMM31H,
  DREG_64_ZMM0H,
  DREG_64_ZMM1H,
  DREG_64_ZMM2H,
  DREG_64_ZMM3H,
  DREG_64_ZMM4H,
  DREG_64_ZMM5H,
  DREG_64_ZMM6H,
  DREG_64_ZMM7H,
  DREG_64_ZMM8H,
  DREG_64_ZMM9H,
  DREG_64_ZMM10H,
  DREG_64_ZMM11H,
  DREG_64_ZMM12H,
  DREG_64_ZMM13H,
  DREG_64_ZMM14H,
  DREG_64_ZMM15H,
  DREG_64_ZMM16H,
  DREG_64_ZMM17H,
  DREG_64_ZMM18H,
  DREG_64_ZMM19H,
  DREG_64_ZMM20H,
  DREG_64_ZMM21H,
  DREG_64_ZMM22H,
  DREG_64_ZMM23H,
  DREG_64_ZMM24H,
  DREG_64_ZMM25H,
  DREG_64_ZMM26H,
  DREG_64_ZMM27H,
  DREG_64_ZMM28H,
  DREG_64_ZMM29H,
  DREG_64_ZMM30H,
  DREG_64_ZMM31H,
  DREG_64_K0,
  DREG_64_K1,
  DREG_64_K2,
  DREG_64_K3,
  DREG_64_K4,
  DREG_64_K5,
  DREG_64_K6,
  DREG_64_K7,
  DREG_64_PKRU,
  DREG_NUM_LINUX_X86_64,
  // Last register we can find in user_regs_struct (except for orig_rax).
  DREG_64_NUM_USER_REGS = DREG_64_GS + 1,

  // aarch64-core.xml
  DREG_X0 = 0,
  DREG_X1,
  DREG_X2,
  DREG_X3,
  DREG_X4,
  DREG_X5,
  DREG_X6,
  DREG_X7,
  DREG_X8,
  DREG_X9,
  DREG_X10,
  DREG_X11,
  DREG_X12,
  DREG_X13,
  DREG_X14,
  DREG_X15,
  DREG_X16,
  DREG_X17,
  DREG_X18,
  DREG_X19,
  DREG_X20,
  DREG_X21,
  DREG_X22,
  DREG_X23,
  DREG_X24,
  DREG_X25,
  DREG_X26,
  DREG_X27,
  DREG_X28,
  DREG_X29,
  DREG_X30,
  DREG_SP,
  DREG_PC,
  DREG_CPSR,

  // aarch64-fpu.xml
  DREG_V0 = 34,
  DREG_V1,
  DREG_V2,
  DREG_V3,
  DREG_V4,
  DREG_V5,
  DREG_V6,
  DREG_V7,
  DREG_V8,
  DREG_V9,
  DREG_V10,
  DREG_V11,
  DREG_V12,
  DREG_V13,
  DREG_V14,
  DREG_V15,
  DREG_V16,
  DREG_V17,
  DREG_V18,
  DREG_V19,
  DREG_V20,
  DREG_V21,
  DREG_V22,
  DREG_V23,
  DREG_V24,
  DREG_V25,
  DREG_V26,
  DREG_V27,
  DREG_V28,
  DREG_V29,
  DREG_V30,
  DREG_V31,
  DREG_FPSR,
  DREG_FPCR,

  DREG_NUM_LINUX_AARCH64 = DREG_FPCR + 1,
};

constexpr const char* reg_name(GdbServerRegister reg) {
  switch (reg) {
    case DREG_64_XMM0:
      return "DREG_64_XMM0";
    case DREG_64_XMM1:
      return "DREG_64_XMM1";
    case DREG_64_XMM2:
      return "DREG_64_XMM2";
    case DREG_64_XMM3:
      return "DREG_64_XMM3";
    case DREG_64_XMM4:
      return "DREG_64_XMM4";
    case DREG_64_XMM5:
      return "DREG_64_XMM5";
    case DREG_64_XMM6:
      return "DREG_64_XMM6";
    case DREG_64_XMM7:
      return "DREG_64_XMM7";
    case DREG_64_XMM8:
      return "DREG_64_XMM8";
    case DREG_64_XMM9:
      return "DREG_64_XMM9";
    case DREG_64_XMM10:
      return "DREG_64_XMM10";
    case DREG_64_XMM11:
      return "DREG_64_XMM11";
    case DREG_64_XMM12:
      return "DREG_64_XMM12";
    case DREG_64_XMM13:
      return "DREG_64_XMM13";
    case DREG_64_XMM14:
      return "DREG_64_XMM14";
    case DREG_64_XMM15:
      return "DREG_64_XMM15";
    case DREG_64_YMM0H:
      return "DREG_64_YMM0H";
    case DREG_64_YMM1H:
      return "DREG_64_YMM1H";
    case DREG_64_YMM2H:
      return "DREG_64_YMM2H";
    case DREG_64_YMM3H:
      return "DREG_64_YMM3H";
    case DREG_64_YMM4H:
      return "DREG_64_YMM4H";
    case DREG_64_YMM5H:
      return "DREG_64_YMM5H";
    case DREG_64_YMM6H:
      return "DREG_64_YMM6H";
    case DREG_64_YMM7H:
      return "DREG_64_YMM7H";
    case DREG_64_YMM8H:
      return "DREG_64_YMM8H";
    case DREG_64_YMM9H:
      return "DREG_64_YMM9H";
    case DREG_64_YMM10H:
      return "DREG_64_YMM10H";
    case DREG_64_YMM11H:
      return "DREG_64_YMM11H";
    case DREG_64_YMM12H:
      return "DREG_64_YMM12H";
    case DREG_64_YMM13H:
      return "DREG_64_YMM13H";
    case DREG_64_YMM14H:
      return "DREG_64_YMM14H";
    case DREG_64_YMM15H:
      return "DREG_64_YMM15H";
    case DREG_64_XMM16:
      return "DREG_64_XMM16";
    case DREG_64_XMM17:
      return "DREG_64_XMM17";
    case DREG_64_XMM18:
      return "DREG_64_XMM18";
    case DREG_64_XMM19:
      return "DREG_64_XMM19";
    case DREG_64_XMM20:
      return "DREG_64_XMM20";
    case DREG_64_XMM21:
      return "DREG_64_XMM21";
    case DREG_64_XMM22:
      return "DREG_64_XMM22";
    case DREG_64_XMM23:
      return "DREG_64_XMM23";
    case DREG_64_XMM24:
      return "DREG_64_XMM24";
    case DREG_64_XMM25:
      return "DREG_64_XMM25";
    case DREG_64_XMM26:
      return "DREG_64_XMM26";
    case DREG_64_XMM27:
      return "DREG_64_XMM27";
    case DREG_64_XMM28:
      return "DREG_64_XMM28";
    case DREG_64_XMM29:
      return "DREG_64_XMM29";
    case DREG_64_XMM30:
      return "DREG_64_XMM30";
    case DREG_64_XMM31:
      return "DREG_64_XMM31";
    case DREG_64_K0:
      return "DREG_64_K0";
    case DREG_64_K1:
      return "DREG_64_K1";
    case DREG_64_K2:
      return "DREG_64_K2";
    case DREG_64_K3:
      return "DREG_64_K3";
    case DREG_64_K4:
      return "DREG_64_K4";
    case DREG_64_K5:
      return "DREG_64_K5";
    case DREG_64_K6:
      return "DREG_64_K6";
    case DREG_64_K7:
      return "DREG_64_K7";
    case DREG_64_ZMM0H:
      return "DREG_64_ZMM0H";
    case DREG_64_ZMM1H:
      return "DREG_64_ZMM1H";
    case DREG_64_ZMM2H:
      return "DREG_64_ZMM2H";
    case DREG_64_ZMM3H:
      return "DREG_64_ZMM3H";
    case DREG_64_ZMM4H:
      return "DREG_64_ZMM4H";
    case DREG_64_ZMM5H:
      return "DREG_64_ZMM5H";
    case DREG_64_ZMM6H:
      return "DREG_64_ZMM6H";
    case DREG_64_ZMM7H:
      return "DREG_64_ZMM7H";
    case DREG_64_ZMM8H:
      return "DREG_64_ZMM8H";
    case DREG_64_ZMM9H:
      return "DREG_64_ZMM9H";
    case DREG_64_ZMM10H:
      return "DREG_64_ZMM10H";
    case DREG_64_ZMM11H:
      return "DREG_64_ZMM11H";
    case DREG_64_ZMM12H:
      return "DREG_64_ZMM12H";
    case DREG_64_ZMM13H:
      return "DREG_64_ZMM13H";
    case DREG_64_ZMM14H:
      return "DREG_64_ZMM14H";
    case DREG_64_ZMM15H:
      return "DREG_64_ZMM15H";
    case DREG_64_ZMM16H:
      return "DREG_64_ZMM16H";
    case DREG_64_ZMM17H:
      return "DREG_64_ZMM17H";
    case DREG_64_ZMM18H:
      return "DREG_64_ZMM18H";
    case DREG_64_ZMM19H:
      return "DREG_64_ZMM19H";
    case DREG_64_ZMM20H:
      return "DREG_64_ZMM20H";
    case DREG_64_ZMM21H:
      return "DREG_64_ZMM21H";
    case DREG_64_ZMM22H:
      return "DREG_64_ZMM22H";
    case DREG_64_ZMM23H:
      return "DREG_64_ZMM23H";
    case DREG_64_ZMM24H:
      return "DREG_64_ZMM24H";
    case DREG_64_ZMM25H:
      return "DREG_64_ZMM25H";
    case DREG_64_ZMM26H:
      return "DREG_64_ZMM26H";
    case DREG_64_ZMM27H:
      return "DREG_64_ZMM27H";
    case DREG_64_ZMM28H:
      return "DREG_64_ZMM28H";
    case DREG_64_ZMM29H:
      return "DREG_64_ZMM29H";
    case DREG_64_ZMM30H:
      return "DREG_64_ZMM30H";
    case DREG_64_ZMM31H:
      return "DREG_64_ZMM31H";
    default:
      return "uninteresting";
  }
}

} // namespace rr

#endif /* RR_GDB_SERVER_REGISTER_H_ */
