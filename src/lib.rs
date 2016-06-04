
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;
use libc::{uint32_t, uint64_t, size_t};

use std::mem;

//
// hv_error.h
//

pub type kern_return_t = ::std::os::raw::c_int;
pub type mach_error_t = kern_return_t;
pub type mach_error_fn_t = ::std::option::Option<extern "C" fn() -> mach_error_t>;
pub type hv_return_t = mach_error_t;

pub const HV_SUCCESS: hv_return_t = 0;
pub const HV_ERROR: hv_return_t = -85377023;
pub const HV_BUSY: hv_return_t = -85377022;
pub const HV_BAD_ARGUMENT: hv_return_t = -85377021;
pub const HV_NO_RESOURCES: hv_return_t = -85377019;
pub const HV_NO_DEVICE: hv_return_t = -85377018;
pub const HV_UNSUPPORTED: hv_return_t = -85377009;

//
// hy_types.h
//

pub type hv_vm_options_t = uint64_t;
pub const HV_VM_DEFAULT: hv_vm_options_t = 0;

pub type hv_vcpu_options_t = uint64_t;
pub const HV_VCPU_DEFAULT: hv_vcpu_options_t = 0; 

pub type hv_memory_flags_t = uint64_t;
pub const HV_MEMORY_READ: hv_memory_flags_t = (1 << 0);
pub const HV_MEMORY_WRITE: hv_memory_flags_t = (1 << 1);
pub const HV_MEMORY_EXEC: hv_memory_flags_t = (1 << 2);

pub type hv_vcpuid_t = ::std::os::raw::c_uint;
pub type hv_uvaddr_t = *const ::std::os::raw::c_void;
pub type hv_gpaddr_t = uint64_t;

//
// hv_arch_x86.h
//

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum hv_x86_reg_t {
    HV_X86_RIP = 0,
    HV_X86_RFLAGS = 1,
    HV_X86_RAX = 2,
    HV_X86_RCX = 3,
    HV_X86_RDX = 4,
    HV_X86_RBX = 5,
    HV_X86_RSI = 6,
    HV_X86_RDI = 7,
    HV_X86_RSP = 8,
    HV_X86_RBP = 9,
    HV_X86_R8 = 10,
    HV_X86_R9 = 11,
    HV_X86_R10 = 12,
    HV_X86_R11 = 13,
    HV_X86_R12 = 14,
    HV_X86_R13 = 15,
    HV_X86_R14 = 16,
    HV_X86_R15 = 17,
    HV_X86_CS = 18,
    HV_X86_SS = 19,
    HV_X86_DS = 20,
    HV_X86_ES = 21,
    HV_X86_FS = 22,
    HV_X86_GS = 23,
    HV_X86_IDT_BASE = 24,
    HV_X86_IDT_LIMIT = 25,
    HV_X86_GDT_BASE = 26,
    HV_X86_GDT_LIMIT = 27,
    HV_X86_LDTR = 28,
    HV_X86_LDT_BASE = 29,
    HV_X86_LDT_LIMIT = 30,
    HV_X86_LDT_AR = 31,
    HV_X86_TR = 32,
    HV_X86_TSS_BASE = 33,
    HV_X86_TSS_LIMIT = 34,
    HV_X86_TSS_AR = 35,
    HV_X86_CR0 = 36,
    HV_X86_CR1 = 37,
    HV_X86_CR2 = 38,
    HV_X86_CR3 = 39,
    HV_X86_CR4 = 40,
    HV_X86_DR0 = 41,
    HV_X86_DR1 = 42,
    HV_X86_DR2 = 43,
    HV_X86_DR3 = 44,
    HV_X86_DR4 = 45,
    HV_X86_DR5 = 46,
    HV_X86_DR6 = 47,
    HV_X86_DR7 = 48,
    HV_X86_TPR = 49,
    HV_X86_XCR0 = 50,
    HV_X86_REGISTERS_MAX = 51,
}

//
// hv_arch_vmx.h
//

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum hv_vmx_vmcs_regs {
    VMCS_VPID                           = 0x00000000,
    VMCS_CTRL_POSTED_INT_N_VECTOR       = 0x00000002,
    VMCS_CTRL_EPTP_INDEX                = 0x00000004,
    VMCS_GUEST_ES                       = 0x00000800,
    VMCS_GUEST_CS                       = 0x00000802,
    VMCS_GUEST_SS                       = 0x00000804,
    VMCS_GUEST_DS                       = 0x00000806,
    VMCS_GUEST_FS                       = 0x00000808,
    VMCS_GUEST_GS                       = 0x0000080a,
    VMCS_GUEST_LDTR                     = 0x0000080c,
    VMCS_GUEST_TR                       = 0x0000080e,
    VMCS_GUEST_INT_STATUS               = 0x00000810,
    VMCS_HOST_ES                        = 0x00000c00,
    VMCS_HOST_CS                        = 0x00000c02,
    VMCS_HOST_SS                        = 0x00000c04,
    VMCS_HOST_DS                        = 0x00000c06,
    VMCS_HOST_FS                        = 0x00000c08,
    VMCS_HOST_GS                        = 0x00000c0a,
    VMCS_HOST_TR                        = 0x00000c0c,
    VMCS_CTRL_IO_BITMAP_A               = 0x00002000,
    VMCS_CTRL_IO_BITMAP_B               = 0x00002002,
    VMCS_CTRL_MSR_BITMAPS               = 0x00002004,
    VMCS_CTRL_VMEXIT_MSR_STORE_ADDR     = 0x00002006,
    VMCS_CTRL_VMEXIT_MSR_LOAD_ADDR      = 0x00002008,
    VMCS_CTRL_VMENTRY_MSR_LOAD_ADDR     = 0x0000200a,
    VMCS_CTRL_EXECUTIVE_VMCS_PTR        = 0x0000200c,
    VMCS_CTRL_TSC_OFFSET                = 0x00002010,
    VMCS_CTRL_VIRTUAL_APIC              = 0x00002012,
    VMCS_CTRL_APIC_ACCESS               = 0x00002014,
    VMCS_CTRL_POSTED_INT_DESC_ADDR      = 0x00002016,
    VMCS_CTRL_VMFUNC_CTRL               = 0x00002018,
    VMCS_CTRL_EPTP                      = 0x0000201a,
    VMCS_CTRL_EOI_EXIT_BITMAP_0         = 0x0000201c,
    VMCS_CTRL_EOI_EXIT_BITMAP_1         = 0x0000201e,
    VMCS_CTRL_EOI_EXIT_BITMAP_2         = 0x00002020,
    VMCS_CTRL_EOI_EXIT_BITMAP_3         = 0x00002022,
    VMCS_CTRL_EPTP_LIST_ADDR            = 0x00002024,
    VMCS_CTRL_VMREAD_BITMAP_ADDR        = 0x00002026,
    VMCS_CTRL_VMWRITE_BITMAP_ADDR       = 0x00002028,
    VMCS_CTRL_VIRT_EXC_INFO_ADDR        = 0x0000202a,
    VMCS_CTRL_XSS_EXITING_BITMAP        = 0x0000202c,
    VMCS_GUEST_PHYSICAL_ADDRESS         = 0x00002400,
    VMCS_GUEST_LINK_POINTER             = 0x00002800,
    VMCS_GUEST_IA32_DEBUGCTL            = 0x00002802,
    VMCS_GUEST_IA32_PAT                 = 0x00002804,
    VMCS_GUEST_IA32_EFER                = 0x00002806,
    VMCS_GUEST_IA32_PERF_GLOBAL_CTRL    = 0x00002808,
    VMCS_GUEST_PDPTE0                   = 0x0000280a,
    VMCS_GUEST_PDPTE1                   = 0x0000280c,
    VMCS_GUEST_PDPTE2                   = 0x0000280e,
    VMCS_GUEST_PDPTE3                   = 0x00002810,
    VMCS_HOST_IA32_PAT                  = 0x00002c00,
    VMCS_HOST_IA32_EFER                 = 0x00002c02,
    VMCS_HOST_IA32_PERF_GLOBAL_CTRL     = 0x00002c04,
    VMCS_CTRL_PIN_BASED                 = 0x00004000,
    VMCS_CTRL_CPU_BASED                 = 0x00004002,
    VMCS_CTRL_EXC_BITMAP                = 0x00004004,
    VMCS_CTRL_PF_ERROR_MASK             = 0x00004006,
    VMCS_CTRL_PF_ERROR_MATCH            = 0x00004008,
    VMCS_CTRL_CR3_COUNT                 = 0x0000400a,
    VMCS_CTRL_VMEXIT_CONTROLS           = 0x0000400c,
    VMCS_CTRL_VMEXIT_MSR_STORE_COUNT    = 0x0000400e,
    VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT     = 0x00004010,
    VMCS_CTRL_VMENTRY_CONTROLS          = 0x00004012,
    VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT    = 0x00004014,
    VMCS_CTRL_VMENTRY_IRQ_INFO          = 0x00004016,
    VMCS_CTRL_VMENTRY_EXC_ERROR         = 0x00004018,
    VMCS_CTRL_VMENTRY_INSTR_LEN         = 0x0000401a,
    VMCS_CTRL_TPR_THRESHOLD             = 0x0000401c,
    VMCS_CTRL_CPU_BASED2                = 0x0000401e,
    VMCS_CTRL_PLE_GAP                   = 0x00004020,
    VMCS_CTRL_PLE_WINDOW                = 0x00004022,
    VMCS_RO_INSTR_ERROR                 = 0x00004400,
    VMCS_RO_EXIT_REASON                 = 0x00004402,
    VMCS_RO_VMEXIT_IRQ_INFO             = 0x00004404,
    VMCS_RO_VMEXIT_IRQ_ERROR            = 0x00004406,
    VMCS_RO_IDT_VECTOR_INFO             = 0x00004408,
    VMCS_RO_IDT_VECTOR_ERROR            = 0x0000440a,
    VMCS_RO_VMEXIT_INSTR_LEN            = 0x0000440c,
    VMCS_RO_VMX_INSTR_INFO              = 0x0000440e,
    VMCS_GUEST_ES_LIMIT                 = 0x00004800,
    VMCS_GUEST_CS_LIMIT                 = 0x00004802,
    VMCS_GUEST_SS_LIMIT                 = 0x00004804,
    VMCS_GUEST_DS_LIMIT                 = 0x00004806,
    VMCS_GUEST_FS_LIMIT                 = 0x00004808,
    VMCS_GUEST_GS_LIMIT                 = 0x0000480a,
    VMCS_GUEST_LDTR_LIMIT               = 0x0000480c,
    VMCS_GUEST_TR_LIMIT                 = 0x0000480e,
    VMCS_GUEST_GDTR_LIMIT               = 0x00004810,
    VMCS_GUEST_IDTR_LIMIT               = 0x00004812,
    VMCS_GUEST_ES_AR                    = 0x00004814,
    VMCS_GUEST_CS_AR                    = 0x00004816,
    VMCS_GUEST_SS_AR                    = 0x00004818,
    VMCS_GUEST_DS_AR                    = 0x0000481a,
    VMCS_GUEST_FS_AR                    = 0x0000481c,
    VMCS_GUEST_GS_AR                    = 0x0000481e,
    VMCS_GUEST_LDTR_AR                  = 0x00004820,
    VMCS_GUEST_TR_AR                    = 0x00004822,
    VMCS_GUEST_IGNORE_IRQ               = 0x00004824,
    VMCS_GUEST_ACTIVITY_STATE           = 0x00004826,
    VMCS_GUEST_SMBASE                   = 0x00004828,
    VMCS_GUEST_IA32_SYSENTER_CS         = 0x0000482a,
    VMCS_GUEST_VMX_TIMER_VALUE          = 0x0000482e,
    VMCS_HOST_IA32_SYSENTER_CS          = 0x00004c00,
    VMCS_CTRL_CR0_MASK                  = 0x00006000,
    VMCS_CTRL_CR4_MASK                  = 0x00006002,
    VMCS_CTRL_CR0_SHADOW                = 0x00006004,
    VMCS_CTRL_CR4_SHADOW                = 0x00006006,
    VMCS_CTRL_CR3_VALUE0                = 0x00006008,
    VMCS_CTRL_CR3_VALUE1                = 0x0000600a,
    VMCS_CTRL_CR3_VALUE2                = 0x0000600c,
    VMCS_CTRL_CR3_VALUE3                = 0x0000600e,
    VMCS_RO_EXIT_QUALIFIC               = 0x00006400,
    VMCS_RO_IO_RCX                      = 0x00006402,
    VMCS_RO_IO_RSI                      = 0x00006404,
    VMCS_RO_IO_RDI                      = 0x00006406,
    VMCS_RO_IO_RIP                      = 0x00006408,
    VMCS_RO_GUEST_LIN_ADDR              = 0x0000640a,
    VMCS_GUEST_CR0                      = 0x00006800,
    VMCS_GUEST_CR3                      = 0x00006802,
    VMCS_GUEST_CR4                      = 0x00006804,
    VMCS_GUEST_ES_BASE                  = 0x00006806,
    VMCS_GUEST_CS_BASE                  = 0x00006808,
    VMCS_GUEST_SS_BASE                  = 0x0000680a,
    VMCS_GUEST_DS_BASE                  = 0x0000680c,
    VMCS_GUEST_FS_BASE                  = 0x0000680e,
    VMCS_GUEST_GS_BASE                  = 0x00006810,
    VMCS_GUEST_LDTR_BASE                = 0x00006812,
    VMCS_GUEST_TR_BASE                  = 0x00006814,
    VMCS_GUEST_GDTR_BASE                = 0x00006816,
    VMCS_GUEST_IDTR_BASE                = 0x00006818,
    VMCS_GUEST_DR7                      = 0x0000681a,
    VMCS_GUEST_RSP                      = 0x0000681c,
    VMCS_GUEST_RIP                      = 0x0000681e,
    VMCS_GUEST_RFLAGS                   = 0x00006820,
    VMCS_GUEST_DEBUG_EXC                = 0x00006822,
    VMCS_GUEST_SYSENTER_ESP             = 0x00006824,
    VMCS_GUEST_SYSENTER_EIP             = 0x00006826,
    VMCS_HOST_CR0                       = 0x00006c00,
    VMCS_HOST_CR3                       = 0x00006c02,
    VMCS_HOST_CR4                       = 0x00006c04,
    VMCS_HOST_FS_BASE                   = 0x00006c06,
    VMCS_HOST_GS_BASE                   = 0x00006c08,
    VMCS_HOST_TR_BASE                   = 0x00006c0a,
    VMCS_HOST_GDTR_BASE                 = 0x00006c0c,
    VMCS_HOST_IDTR_BASE                 = 0x00006c0e,
    VMCS_HOST_IA32_SYSENTER_ESP         = 0x00006c10,
    VMCS_HOST_IA32_SYSENTER_EIP         = 0x00006c12,
    VMCS_HOST_RSP                       = 0x00006c14,
    VMCS_HOST_RIP                       = 0x00006c16,
    VMCS_MAX                            = 0x00006c18
}

pub const VMX_BASIC_TRUE_CTLS: u64          = (1 << 55);

pub const PIN_BASED_INTR: u32               = (1 << 0);
pub const PIN_BASED_NMI: u32                = (1 << 3);
pub const PIN_BASED_VIRTUAL_NMI: u32        = (1 << 5);
pub const PIN_BASED_PREEMPTION_TIMER: u32   = (1 << 6);
pub const PIN_BASED_POSTED_INTR: u32        = (1 << 7);

pub const CPU_BASED_IRQ_WND: u32            = (1 << 2);
pub const CPU_BASED_TSC_OFFSET: u32         = (1 << 3);
pub const CPU_BASED_HLT: u32                = (1 << 7);
pub const CPU_BASED_INVLPG: u32             = (1 << 9);
pub const CPU_BASED_MWAIT: u32              = (1 << 10);
pub const CPU_BASED_RDPMC: u32              = (1 << 11);
pub const CPU_BASED_RDTSC: u32              = (1 << 12);
pub const CPU_BASED_CR3_LOAD: u32           = (1 << 15);
pub const CPU_BASED_CR3_STORE: u32          = (1 << 16);
pub const CPU_BASED_CR8_LOAD: u32           = (1 << 19);
pub const CPU_BASED_CR8_STORE: u32          = (1 << 20);
pub const CPU_BASED_TPR_SHADOW: u32         = (1 << 21);
pub const CPU_BASED_VIRTUAL_NMI_WND: u32    = (1 << 22);
pub const CPU_BASED_MOV_DR: u32             = (1 << 23);
pub const CPU_BASED_UNCOND_IO: u32          = (1 << 24);
pub const CPU_BASED_IO_BITMAPS: u32         = (1 << 25);
pub const CPU_BASED_MTF: u32                = (1 << 27);
pub const CPU_BASED_MSR_BITMAPS: u32        = (1 << 28);
pub const CPU_BASED_MONITOR: u32            = (1 << 29);
pub const CPU_BASED_PAUSE: u32              = (1 << 30);
pub const CPU_BASED_SECONDARY_CTLS: u32     = (1 << 31);

pub const CPU_BASED2_VIRTUAL_APIC: u32      = (1 << 0);
pub const CPU_BASED2_EPT: u32               = (1 << 1);
pub const CPU_BASED2_DESC_TABLE: u32        = (1 << 2);
pub const CPU_BASED2_RDTSCP: u32            = (1 << 3);
pub const CPU_BASED2_X2APIC: u32            = (1 << 4);
pub const CPU_BASED2_VPID: u32              = (1 << 5);
pub const CPU_BASED2_WBINVD: u32            = (1 << 6);
pub const CPU_BASED2_UNRESTRICTED: u32      = (1 << 7);
pub const CPU_BASED2_APIC_REG_VIRT: u32     = (1 << 8);
pub const CPU_BASED2_VIRT_INTR_DELIVERY: u32= (1 << 9);
pub const CPU_BASED2_PAUSE_LOOP: u32        = (1 << 10);
pub const CPU_BASED2_RDRAND: u32            = (1 << 11);
pub const CPU_BASED2_INVPCID: u32           = (1 << 12);
pub const CPU_BASED2_VMFUNC: u32            = (1 << 13);
pub const CPU_BASED2_VMCS_SHADOW: u32       = (1 << 14);
pub const CPU_BASED2_RDSEED: u32            = (1 << 16);
pub const CPU_BASED2_EPT_VE: u32            = (1 << 18);
pub const CPU_BASED2_XSAVES_XRSTORS: u32    = (1 << 20);

pub const VMX_EPT_VPID_SUPPORT_AD: u32      = (1 << 21);
pub const VMX_EPT_VPID_SUPPORT_EXONLY: u32  = (1 << 0);

pub const VMEXIT_SAVE_DBG_CONTROLS: u32            = (1 << 2);
pub const VMEXIT_HOST_IA32E: u32                   = (1 << 9);
pub const VMEXIT_LOAD_IA32_PERF_GLOBAL_CTRL: u32   = (1 << 12);
pub const VMEXIT_ACK_INTR: u32                     = (1 << 15);
pub const VMEXIT_SAVE_IA32_PAT: u32                = (1 << 18);
pub const VMEXIT_LOAD_IA32_PAT: u32                = (1 << 19);
pub const VMEXIT_SAVE_EFER: u32                    = (1 << 20);
pub const VMEXIT_LOAD_EFER: u32                    = (1 << 21);
pub const VMEXIT_SAVE_VMX_TIMER: u32               = (1 << 22);

pub const VMENTRY_LOAD_DBG_CONTROLS: u32           = (1 << 2);
pub const VMENTRY_GUEST_IA32E: u32                 = (1 << 9);
pub const VMENTRY_SMM: u32                         = (1 << 10);
pub const VMENTRY_DEACTIVATE_DUAL_MONITOR: u32     = (1 << 11);
pub const VMENTRY_LOAD_IA32_PERF_GLOBAL_CTRL: u32  = (1 << 13);
pub const VMENTRY_LOAD_IA32_PAT: u32               = (1 << 14);
pub const VMENTRY_LOAD_EFER: u32                   = (1 << 15);

pub const IRQ_INFO_EXT_IRQ: u32         = (0 << 8);
pub const IRQ_INFO_NMI: u32             = (2 << 8);
pub const IRQ_INFO_HARD_EXC: u32        = (3 << 8);
pub const IRQ_INFO_SOFT_IRQ: u32        = (4 << 8);
pub const IRQ_INFO_PRIV_SOFT_EXC: u32   = (5 << 8);
pub const IRQ_INFO_SOFT_EXC: u32        = (6 << 8);
pub const IRQ_INFO_ERROR_VALID: u32     = (1 << 11);
pub const IRQ_INFO_VALID: u32           = (1 << 31);

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum hv_vmx_exit_reason {
    VMX_REASON_EXC_NMI                  = 0,
    VMX_REASON_IRQ                      = 1,
    VMX_REASON_TRIPLE_FAULT             = 2,
    VMX_REASON_INIT                     = 3,
    VMX_REASON_SIPI                     = 4,
    VMX_REASON_IO_SMI                   = 5,
    VMX_REASON_OTHER_SMI                = 6,
    VMX_REASON_IRQ_WND                  = 7,
    VMX_REASON_VIRTUAL_NMI_WND          = 8,
    VMX_REASON_TASK                     = 9,
    VMX_REASON_CPUID                    = 10,
    VMX_REASON_GETSEC                   = 11,
    VMX_REASON_HLT                      = 12,
    VMX_REASON_INVD                     = 13,
    VMX_REASON_INVLPG                   = 14,
    VMX_REASON_RDPMC                    = 15,
    VMX_REASON_RDTSC                    = 16,
    VMX_REASON_RSM                      = 17,
    VMX_REASON_VMCALL                   = 18,
    VMX_REASON_VMCLEAR                  = 19,
    VMX_REASON_VMLAUNCH                 = 20,
    VMX_REASON_VMPTRLD                  = 21,
    VMX_REASON_VMPTRST                  = 22,
    VMX_REASON_VMREAD                   = 23,
    VMX_REASON_VMRESUME                 = 24,
    VMX_REASON_VMWRITE                  = 25,
    VMX_REASON_VMOFF                    = 26,
    VMX_REASON_VMON                     = 27,
    VMX_REASON_MOV_CR                   = 28,
    VMX_REASON_MOV_DR                   = 29,
    VMX_REASON_IO                       = 30,
    VMX_REASON_RDMSR                    = 31,
    VMX_REASON_WRMSR                    = 32,
    VMX_REASON_VMENTRY_GUEST            = 33,
    VMX_REASON_VMENTRY_MSR              = 34,
    VMX_REASON_MWAIT                    = 36,
    VMX_REASON_MTF                      = 37,
    VMX_REASON_MONITOR                  = 39,
    VMX_REASON_PAUSE                    = 40,
    VMX_REASON_VMENTRY_MC               = 41,
    VMX_REASON_TPR_THRESHOLD            = 43,
    VMX_REASON_APIC_ACCESS              = 44,
    VMX_REASON_VIRTUALIZED_EOI          = 45,
    VMX_REASON_GDTR_IDTR                = 46,
    VMX_REASON_LDTR_TR                  = 47,
    VMX_REASON_EPT_VIOLATION            = 48,
    VMX_REASON_EPT_MISCONFIG            = 49,
    VMX_REASON_EPT_INVEPT               = 50,
    VMX_REASON_RDTSCP                   = 51,
    VMX_REASON_VMX_TIMER_EXPIRED        = 52,
    VMX_REASON_INVVPID                  = 53,
    VMX_REASON_WBINVD                   = 54,
    VMX_REASON_XSETBV                   = 55,
    VMX_REASON_APIC_WRITE               = 56,
    VMX_REASON_RDRAND                   = 57,
    VMX_REASON_INVPCID                  = 58,
    VMX_REASON_VMFUNC                   = 59,
    VMX_REASON_RDSEED                   = 61,
    VMX_REASON_XSAVES                   = 63,
    VMX_REASON_XRSTORS                  = 64
}

/**
 * Convert u32 to a valid exit reason
 */
impl hv_vmx_exit_reason {
    pub fn from_u32(n: u32) -> Option<hv_vmx_exit_reason> {
        if n <= 64 {
            Some(unsafe { mem::transmute(n) })
        } else {
            None
        }
    }
}

//
// hv_vmx.h
//

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum hv_vmx_capability_t {
	HV_VMX_CAP_PINBASED = 0,
	HV_VMX_CAP_PROCBASED = 1,
	HV_VMX_CAP_PROCBASED2 = 2,
	HV_VMX_CAP_ENTRY = 3,
	HV_VMX_CAP_EXIT = 4,
	HV_VMX_CAP_PREEMPTION_TIMER = 32
}

#[link(name = "Hypervisor", kind = "framework")]
extern "C" {
    pub fn hv_vmx_vcpu_read_vmcs(vcpu: hv_vcpuid_t, field: uint32_t, value: *mut uint64_t) -> hv_return_t;
    pub fn hv_vmx_vcpu_write_vmcs(vcpu: hv_vcpuid_t, field: uint32_t, value: uint64_t) -> hv_return_t;
    pub fn hv_vmx_read_capability(field: hv_vmx_capability_t, value: *mut uint64_t) -> hv_return_t;
    pub fn hv_vmx_vcpu_set_apic_address(vcpu: hv_vcpuid_t, gpa: hv_gpaddr_t) -> hv_return_t;
}

//
// hv.h
//

#[link(name = "Hypervisor", kind = "framework")]
extern "C" {
    pub fn hv_vm_create(flags: hv_vm_options_t) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    pub fn hv_vm_map(uva: hv_uvaddr_t, gpa: hv_gpaddr_t, size: size_t, flags: hv_memory_flags_t) -> hv_return_t;
    pub fn hv_vm_unmap(gpa: hv_gpaddr_t, size: size_t) -> hv_return_t;
    pub fn hv_vm_protect(gpa: hv_gpaddr_t, size: size_t, flags: hv_memory_flags_t) -> hv_return_t;
    pub fn hv_vm_sync_tsc(tsc: uint64_t) -> hv_return_t;
    pub fn hv_vcpu_create(vcpu: *mut hv_vcpuid_t, flags: hv_vcpu_options_t) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpuid_t) -> hv_return_t;
    pub fn hv_vcpu_read_register(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t, value: *mut uint64_t) -> hv_return_t;
    pub fn hv_vcpu_write_register(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t, value: uint64_t) -> hv_return_t;
    pub fn hv_vcpu_read_fpstate(vcpu: hv_vcpuid_t, buffer: *mut ::std::os::raw::c_void, size: size_t) -> hv_return_t;
    pub fn hv_vcpu_write_fpstate(vcpu: hv_vcpuid_t, buffer: *mut ::std::os::raw::c_void, size: size_t) -> hv_return_t;
    pub fn hv_vcpu_enable_native_msr(vcpu: hv_vcpuid_t, msr: uint32_t, enable: u8) -> hv_return_t;
    pub fn hv_vcpu_read_msr(vcpu: hv_vcpuid_t, msr: uint32_t, value: *mut uint64_t) -> hv_return_t;
    pub fn hv_vcpu_write_msr(vcpu: hv_vcpuid_t, msr: uint32_t, value: uint64_t) -> hv_return_t;
    pub fn hv_vcpu_flush(vcpu: hv_vcpuid_t) -> hv_return_t;
    pub fn hv_vcpu_invalidate_tlb(vcpu: hv_vcpuid_t) -> hv_return_t;
    pub fn hv_vcpu_run(vcpu: hv_vcpuid_t) -> hv_return_t;
    pub fn hv_vcpu_interrupt(vcpus: *mut hv_vcpuid_t, vcpu_count: ::std::os::raw::c_uint) -> hv_return_t;
    pub fn hv_vcpu_get_exec_time(vcpu: hv_vcpuid_t, time: *mut uint64_t) -> hv_return_t;
}
