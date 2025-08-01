//! Rust equivalents for core data structures used by the .NET GC interface.
//!
//! This module provides FFI-safe representations of structs and enums
//! that are passed between the runtime (EE) and the Garbage Collector.

use bitflags::bitflags;
use std::ffi::c_void;
use std::fmt;

// --- Enums ---

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleType {
    HndtypeWeakShort = 0,
    HndtypeWeakLong = 1,
    // HNDTYPE_WEAK_DEFAULT = 1,
    HndtypeStrong = 2,
    // HNDTYPE_DEFAULT = 2,
    HndtypePinned = 3,
    HndtypeVariable = 4,
    HndtypeRefcounted = 5,
    HndtypeDependent = 6,
    HndtypeAsyncpinned = 7,
    HndtypeSizedref = 8,
    HndtypeWeakNativeCom = 9,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteBarrierOp {
    StompResize,
    StompEphemeral,
    Initialize,
    SwitchToWriteWatch,
    SwitchToNonWriteWatch,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum walk_surv_type {
    WalkForGc = 1,
    WalkForBgc = 2,
    WalkForUoh = 3,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GCEventLevel {
    None = 0,
    Fatal = 1,
    Error = 2,
    Warning = 3,
    Information = 4,
    Verbose = 5,
    Max = 6,
    LogAlways = 255,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum enable_no_gc_region_callback_status {
    Succeed,
    NotStarted,
    InsufficientBudget,
    AlreadyRegistered,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SUSPEND_REASON {
    SuspendForGc = 1,
    SuspendForGcPrep = 6,
}

// --- Bitflag Enums ---
bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GCEventKeyword: u32 {
        const NONE = 0x0;
        const GC = 0x1;
        const GC_PRIVATE = 0x1; // Duplicate on purpose
        const GC_HANDLE = 0x2;
        const GC_HANDLE_PRIVATE = 0x4000;
        const GC_HEAP_DUMP = 0x100000;
        const GC_SAMPLED_OBJECT_ALLOCATION_HIGH = 0x200000;
        const GC_HEAP_SURVIVAL_AND_MOVEMENT = 0x400000;
        const GC_HEAP_COLLECT = 0x800000;
        const GC_HEAP_AND_TYPE_NAMES = 0x1000000;
        const GC_SAMPLED_OBJECT_ALLOCATION_LOW = 0x2000000;
        const ALL = Self::GC.bits()
                | Self::GC_HANDLE.bits()
                | Self::GC_HANDLE_PRIVATE.bits()
                | Self::GC_HEAP_DUMP.bits()
                | Self::GC_SAMPLED_OBJECT_ALLOCATION_HIGH.bits()
                | Self::GC_HEAP_SURVIVAL_AND_MOVEMENT.bits()
                | Self::GC_HEAP_COLLECT.bits()
                | Self::GC_HEAP_AND_TYPE_NAMES.bits()
                | Self::GC_SAMPLED_OBJECT_ALLOCATION_LOW.bits();
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GcAllocFlags: u32 {
        const NO_FLAGS = 0;
        const FINALIZE = 1;
        const CONTAINS_REF = 2;
        const ALIGN8_BIAS = 4;
        const ALIGN8 = 8;
        const ZEROING_OPTIONAL = 16;
        const LARGE_OBJECT_HEAP = 32;
        const PINNED_OBJECT_HEAP = 64;
        const USER_OLD_HEAP = Self::LARGE_OBJECT_HEAP.bits() | Self::PINNED_OBJECT_HEAP.bits();
    }
}

// --- Structs ---
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GcDacVars {
    pub major_version_number: u8,
    pub minor_version_number: u8,
    pub generation_size: isize,
    pub total_generation_count: isize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VersionInfo {
    pub major_version: i32,
    pub minor_version: i32,
    pub build_version: i32,
    pub name: *mut u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ObjectHandle {
    /// Pointer to the managed object. This should be treated as atomic
    /// in implementations due to `Interlocked.CompareExchange` usage.
    pub object: isize,
    pub extra_info: isize,
    pub handle_type: HandleType,
}

impl fmt::Display for ObjectHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} - {:#x} - {:#x}",
            self.handle_type, self.object, self.extra_info
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GCObject {
    pub method_table: isize, // Equivalent to IntPtr
    pub length: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WriteBarrierParameters {
    pub operation: WriteBarrierOp,
    pub is_runtime_suspended: bool,
    pub requires_upper_bounds_check: bool,
    pub card_table: *mut u32,
    pub card_bundle_table: *mut u32,
    pub lowest_address: isize,
    pub highest_address: isize,
    pub ephemeral_low: isize,
    pub ephemeral_high: isize,
    pub write_watch_table: *mut u8,
    pub region_to_generation_table: *mut u8,
    pub region_shr: u8,
    pub region_use_bitwise_write_barrier: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct gc_alloc_context {
    pub alloc_ptr: isize,
    pub alloc_limit: isize,
    pub alloc_bytes: i64,
    pub alloc_bytes_uoh: i64,
    pub gc_reserved_1: *mut c_void,
    pub gc_reserved_2: *mut c_void,
    pub alloc_count: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct segment_info {
    pub pv_mem: *mut c_void,
    pub ib_first_object: isize,
    pub ib_allocated: isize,
    pub ib_commit: isize,
    pub ib_reserved: isize,
}
