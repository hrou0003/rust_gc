//! Rust FFI bindings for the .NET Garbage Collector interface (gcinterface.h).
//!
//! This module provides the necessary type definitions, constants, and interface
//! traits to allow building a custom .NET GC in Rust.
//!
//! To use this, you would:
//! 1. Create a Rust library (a cdylib).
//! 2. Implement the `IGCHeap` and `IGCHandleManager` traits for your GC structs.
//! 3. Create static VTables for your implementations.
//! 4. Implement and export the `GC_Initialize` function, which the .NET runtime
//!    will call to get instances of your GC.

// We use the libc crate for C-compatible types.
// The bitflags crate is excellent for C-style bitflag enums.
// Add to your Cargo.toml:
// [dependencies]
// libc = "0.2"
// bitflags = "2.5"

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use bitflags::bitflags;
use std::{
    ffi::c_uint,
    os::raw::{c_char, c_float, c_int, c_void},
};
use crate::IGCToCLRVTable;

// C++ HRESULT is a 32-bit signed integer on Windows.
pub type HRESULT = i32;

// --- Opaque Types and Forward Declarations ---
// These are types defined elsewhere (like gcinterface.ee.h) or are used as opaque pointers.
// We define them as empty, C-compatible structs for type safety in pointers.

#[repr(C)]
pub struct Object {
    _private: [u8; 0],
}
#[repr(C)]
pub struct CrawlFrame {
    _private: [u8; 0],
}
#[repr(C)]
pub struct Thread {
    _private: [u8; 0],
}
#[repr(C)]
pub struct gc_heap_segment_stub {
    _private: [u8; 0],
}
#[repr(C)]
pub struct OBJECTHANDLE__ {
    _private: [u8; 0],
}
#[repr(C)]
pub struct IGCToCLR {
    pub vtable: *const IGCToCLRVTable,
}

#[repr(C)]
pub struct GcDacVars {
    pub major_version_number: u8,
    pub minor_version_number: u8,
    pub generation_size: isize,
    pub total_generation_count: isize,
}

// --- Pointer Type Aliases ---
pub type segment_handle = *mut gc_heap_segment_stub;
pub type OBJECTHANDLE = *mut OBJECTHANDLE__;
pub type PTR_PTR_Object = *mut *mut Object;
pub type PTR_UNCHECKED_OBJECTREF = *mut Object;

// --- Constants ---
pub const GC_INTERFACE_MAJOR_VERSION: u32 = 5;
pub const GC_INTERFACE_MINOR_VERSION: u32 = 3;
pub const EE_INTERFACE_MAJOR_VERSION: u32 = 3;

pub const LARGE_OBJECT_SIZE: usize = 85000;
pub const min_obj_size: usize = std::mem::size_of::<*mut u8>() * 3;
pub const SOFTWARE_WRITE_WATCH_AddressToTableByteIndexShift: u32 = 0xc;

// Constants for the flags parameter to the GC callback
pub const GC_CALL_INTERIOR: u32 = 0x1;
pub const GC_CALL_PINNED: u32 = 0x2;

// --- Function Pointer Typedefs ---
pub type promote_func =
    Option<extern "C" fn(obj: PTR_PTR_Object, sc: *mut ScanContext, flags: u32)>;
pub type enum_alloc_context_func =
    Option<extern "C" fn(ac: *mut gc_alloc_context, data: *mut c_void)>;

// The __stdcall calling convention is for 32-bit Windows. Other platforms use C convention.
#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub type GCBackgroundThreadFunction = Option<extern "stdcall" fn(param: *mut c_void) -> u32>;
#[cfg(not(all(target_os = "windows", target_arch = "x86")))]
pub type GCBackgroundThreadFunction = Option<extern "C" fn(param: *mut c_void) -> u32>;

#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub type HANDLESCANPROC = Option<
    extern "stdcall" fn(
        pref: PTR_UNCHECKED_OBJECTREF,
        pExtraInfo: *mut usize,
        param1: usize,
        param2: usize,
    ),
>;
#[cfg(not(all(target_os = "windows", target_arch = "x86")))]
pub type HANDLESCANPROC = Option<
    extern "C" fn(
        pref: PTR_UNCHECKED_OBJECTREF,
        pExtraInfo: *mut usize,
        param1: usize,
        param2: usize,
    ),
>;

pub type walk_fn = Option<extern "C" fn(obj: *mut Object, context: *mut c_void) -> bool>;
pub type walk_fn2 =
    Option<extern "C" fn(obj: *mut Object, pb: *mut *mut u8, context: *mut c_void) -> bool>;
pub type gen_walk_fn = Option<
    extern "C" fn(
        context: *mut c_void,
        generation: c_int,
        range_start: *mut u8,
        range_end: *mut u8,
        range_reserved: *mut u8,
    ),
>;
pub type record_surv_fn = Option<
    extern "C" fn(
        begin: *mut u8,
        end: *mut u8,
        reloc: isize,
        context: *mut c_void,
        compacting_p: bool,
        bgc_p: bool,
    ),
>;
pub type fq_walk_fn = Option<extern "C" fn(is_critical: bool, p_object: *mut c_void)>;
pub type fq_scan_fn =
    Option<extern "C" fn(pp_object: *mut *mut Object, p_sc: *mut ScanContext, dw_flags: u32)>;
pub type handle_scan_fn = Option<
    extern "C" fn(
        p_ref: *mut *mut Object,
        p_sec: *mut Object,
        flags: u32,
        context: *mut ScanContext,
        is_dependent: bool,
    ),
>;
pub type async_pin_enum_fn =
    Option<extern "C" fn(object: *mut Object, context: *mut c_void) -> bool>;

// --- Enums ---

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SUSPEND_REASON {
    SUSPEND_FOR_GC = 1,
    SUSPEND_FOR_GC_PREP = 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum walk_surv_type {
    walk_for_gc = 1,
    walk_for_bgc = 2,
    walk_for_uoh = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteBarrierOp {
    StompResize,
    StompEphemeral,
    Initialize,
    SwitchToWriteWatch,
    SwitchToNonWriteWatch,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GCEventProvider {
    Default = 0,
    Private = 1,
}

#[repr(C)]
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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum wait_full_gc_status {
    wait_full_gc_success = 0,
    wait_full_gc_failed = 1,
    wait_full_gc_cancelled = 2,
    wait_full_gc_timeout = 3,
    wait_full_gc_na = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum start_no_gc_region_status {
    start_no_gc_success = 0,
    start_no_gc_no_memory = 1,
    start_no_gc_too_large = 2,
    start_no_gc_in_progress = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum end_no_gc_region_status {
    end_no_gc_success = 0,
    end_no_gc_not_in_progress = 1,
    end_no_gc_induced = 2,
    end_no_gc_alloc_exceeded = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum refresh_memory_limit_status {
    refresh_success = 0,
    refresh_hard_limit_too_low = 1,
    refresh_hard_limit_invalid = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum enable_no_gc_region_callback_status {
    succeed,
    not_started,
    insufficient_budget,
    already_registered,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum gc_kind {
    gc_kind_any = 0,
    gc_kind_ephemeral = 1,
    gc_kind_full_blocking = 2,
    gc_kind_background = 3,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleType {
    WEAK_SHORT = 0,
    WEAK_LONG = 1,
    STRONG = 2,
    PINNED = 3,
    VARIABLE = 4,
    REFCOUNTED = 5,
    DEPENDENT = 6,
    ASYNCPINNED = 7,
    SIZEDREF = 8,
    WEAK_NATIVE_COM = 9,
    WEAK_INTERIOR_POINTER = 10,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GCHeapType {
    GC_HEAP_INVALID = 0,
    GC_HEAP_WKS = 1,
    GC_HEAP_SVR = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GCConfigurationType {
    Int64,
    StringUtf8,
    Boolean,
}

// ETW Root Kind (incomplete, stubbed as u32)
// The full definition is in EtwRedhawk.h, but for FFI, an integer type is often sufficient.
pub type EtwGCRootKind = u32;

// --- Bitflags ---

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct GCEventKeyword: u64 {
        const None = 0;
        const GC = 0x1;
        const GCPrivate = 0x1;
        const GCHandle = 0x2;
        const GCHandlePrivate = 0x4000;
        const GCHeapDump = 0x100000;
        const GCSampledObjectAllocationHigh = 0x200000;
        const GCHeapSurvivalAndMovement = 0x400000;
        const ManagedHeapCollect = 0x800000;
        const GCHeapAndTypeNames = 0x1000000;
        const GCSampledObjectAllocationLow = 0x2000000;
        const All =
            Self::GC.bits() |
            Self::GCPrivate.bits() |
            Self::GCHandle.bits() |
            Self::GCHandlePrivate.bits() |
            Self::GCHeapDump.bits() |
            Self::GCSampledObjectAllocationHigh.bits() |
            Self::GCHeapSurvivalAndMovement.bits() |
            Self::ManagedHeapCollect.bits() |
            Self::GCHeapAndTypeNames.bits() |
            Self::GCSampledObjectAllocationLow.bits();
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct collection_mode: u32 {
        const non_blocking = 0x00000001;
        const blocking = 0x00000002;
        const optimized = 0x00000004;
        const compacting = 0x00000008;
        const aggressive = 0x00000010;
        #[cfg(feature = "stress_heap")]
        const gcstress = 0x80000000;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct GC_ALLOC_FLAGS: u32 {
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
#[derive(Debug, Copy, Clone)]
pub struct WriteBarrierParameters {
    pub operation: WriteBarrierOp,
    pub is_runtime_suspended: bool,
    pub requires_upper_bounds_check: bool,
    pub card_table: *mut u32,
    pub card_bundle_table: *mut u32,
    pub lowest_address: *mut u8,
    pub highest_address: *mut u8,
    pub ephemeral_low: *mut u8,
    pub ephemeral_high: *mut u8,
    pub write_watch_table: *mut u8,
    pub region_to_generation_table: *mut u8,
    pub region_shr: u8,
    pub region_use_bitwise_write_barrier: bool,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FinalizerWorkItem {
    pub next: *mut FinalizerWorkItem,
    pub callback: Option<extern "C" fn(item: *mut FinalizerWorkItem)>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NoGCRegionCallbackFinalizerWorkItem {
    // C++ inheritance is modeled by composition of the base struct as the first field.
    pub base: FinalizerWorkItem,
    pub scheduled: bool,
    pub abandoned: bool,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EtwGCSettingsInfo {
    pub heap_hard_limit: usize,
    pub loh_threshold: usize,
    pub physical_memory_from_config: usize,
    pub gen0_min_budget_from_config: usize,
    pub gen0_max_budget_from_config: usize,
    pub high_mem_percent_from_config: u32,
    pub concurrent_gc_p: bool,
    pub use_large_pages_p: bool,
    pub use_frozen_segments_p: bool,
    pub hard_limit_config_p: bool,
    pub no_affinitize_p: bool,
}

#[repr(C)]
#[derive(Debug)]
pub struct gc_alloc_context {
    pub alloc_ptr: *mut u8,
    pub alloc_limit: *mut u8,
    pub alloc_bytes: i64,
    pub alloc_bytes_uoh: i64,
    pub gc_reserved_1: *mut c_void,
    pub gc_reserved_2: *mut c_void,
    pub alloc_count: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct segment_info {
    pub pvMem: *mut c_void,
    pub ibFirstObject: usize,
    pub ibAllocated: usize,
    pub ibCommit: usize,
    pub ibReserved: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct ScanContext {
    pub thread_under_crawl: *mut Thread,
    pub thread_number: c_int,
    pub thread_count: c_int,
    pub stack_limit: usize,
    pub promotion: bool,
    pub concurrent: bool,
    pub _unused1: *mut c_void,
    pub pMD: *mut c_void,
    pub dwEtwRootKind: EtwGCRootKind,
}

impl Default for ScanContext {
    fn default() -> Self {
        ScanContext {
            thread_under_crawl: std::ptr::null_mut(),
            thread_number: -1,
            thread_count: -1,
            stack_limit: 0,
            promotion: false,
            concurrent: false,
            _unused1: std::ptr::null_mut(),
            pMD: std::ptr::null_mut(),
            dwEtwRootKind: 0, // kEtwGCRootKindOther
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VersionInfo {
    pub major_version: u32,
    pub minor_version: u32,
    pub build_version: u32,
    pub c: *const c_char,
}

// --- FFI Interfaces (Traits and VTables) ---

// The pattern for C++ interfaces is:
// 1. A Rust `trait` that defines the high-level API.
// 2. An `FFI` struct (e.g., `IGCHeapFFI`) which is a handle that C++ sees. Its
//    first field must be a pointer to the VTable.
// 3. A `VTable` struct containing function pointers for each virtual method.
// 4. Your GC implementation will provide a static instance of this VTable.

// --- IGCHandleStore ---
#[repr(C)]
pub struct IGCHandleStoreFFI {
    pub vtable: *const IGCHandleStoreVTable,
}
pub trait IGCHandleStore {
    fn uproot(&mut self);
    fn contains_handle(&mut self, handle: OBJECTHANDLE) -> bool;
    fn create_handle_of_type(&mut self, object: *mut Object, type_: HandleType) -> OBJECTHANDLE;
    fn create_handle_of_type_with_heap_affinity(
        &mut self,
        object: *mut Object,
        type_: HandleType,
        heap_to_affinitize_to: c_int,
    ) -> OBJECTHANDLE;
    fn create_handle_with_extra_info(
        &mut self,
        object: *mut Object,
        type_: HandleType,
        p_extra_info: *mut c_void,
    ) -> OBJECTHANDLE;
    fn create_dependent_handle(
        &mut self,
        primary: *mut Object,
        secondary: *mut Object,
    ) -> OBJECTHANDLE;
}
#[repr(C)]
pub struct IGCHandleStoreVTable {
    pub Uproot: extern "C" fn(this: *mut IGCHandleStoreFFI),
    pub ContainsHandle: extern "C" fn(this: *mut IGCHandleStoreFFI, handle: OBJECTHANDLE) -> bool,
    pub CreateHandleOfType: extern "C" fn(
        this: *mut IGCHandleStoreFFI,
        object: *mut Object,
        type_: HandleType,
    ) -> OBJECTHANDLE,
    pub CreateHandleOfType_HeapAffinitized: extern "C" fn(
        this: *mut IGCHandleStoreFFI,
        object: *mut Object,
        type_: HandleType,
        heapToAffinitizeTo: c_int,
    ) -> OBJECTHANDLE,
    pub CreateHandleWithExtraInfo: extern "C" fn(
        this: *mut IGCHandleStoreFFI,
        object: *mut Object,
        type_: HandleType,
        pExtraInfo: *mut c_void,
    ) -> OBJECTHANDLE,
    pub CreateDependentHandle: extern "C" fn(
        this: *mut IGCHandleStoreFFI,
        primary: *mut Object,
        secondary: *mut Object,
    ) -> OBJECTHANDLE,
}

// --- IGCHandleManager ---
#[repr(C)]
pub struct IGCHandleManagerFFI {
    pub vtable: *const IGCHandleManagerVTable,
}

pub trait IGCHandleManager {
    fn initialize(&mut self) -> bool;
    fn shutdown(&mut self);
    fn get_global_handle_store(&mut self) -> *mut IGCHandleStoreFFI;
    fn create_handle_store(&mut self) -> *mut IGCHandleStoreFFI;
    fn destroy_handle_store(&mut self, store: *mut IGCHandleStoreFFI);
    fn create_global_handle_of_type(
        &mut self,
        object: *mut Object,
        type_: HandleType,
    ) -> OBJECTHANDLE;
    fn create_duplicate_handle(&mut self, handle: OBJECTHANDLE) -> OBJECTHANDLE;
    fn destroy_handle_of_type(&mut self, handle: OBJECTHANDLE, type_: HandleType);
    fn destroy_handle_of_unknown_type(&mut self, handle: OBJECTHANDLE);
    fn set_extra_info_for_handle(
        &mut self,
        handle: OBJECTHANDLE,
        type_: HandleType,
        p_extra_info: *mut c_void,
    );
    fn get_extra_info_from_handle(&mut self, handle: OBJECTHANDLE) -> *mut c_void;
    fn store_object_in_handle(&mut self, handle: OBJECTHANDLE, object: *mut Object);
    fn store_object_in_handle_if_null(&mut self, handle: OBJECTHANDLE, object: *mut Object)
        -> bool;
    fn set_dependent_handle_secondary(&mut self, handle: OBJECTHANDLE, object: *mut Object);
    fn get_dependent_handle_secondary(&mut self, handle: OBJECTHANDLE) -> *mut Object;
    fn interlocked_compare_exchange_object_in_handle(
        &mut self,
        handle: OBJECTHANDLE,
        object: *mut Object,
        comparand_object: *mut Object,
    ) -> *mut Object;
    fn handle_fetch_type(&mut self, handle: OBJECTHANDLE) -> HandleType;
    fn trace_ref_counted_handles(&mut self, callback: HANDLESCANPROC, param1: usize, param2: usize);
}
#[repr(C)]
pub struct IGCHandleManagerVTable {
    pub Initialize: extern "C" fn(this: *mut IGCHandleManagerFFI) -> bool,
    pub Shutdown: extern "C" fn(this: *mut IGCHandleManagerFFI),
    pub GetGlobalHandleStore:
        extern "C" fn(this: *mut IGCHandleManagerFFI) -> *mut IGCHandleStoreFFI,
    pub CreateHandleStore: extern "C" fn(this: *mut IGCHandleManagerFFI) -> *mut IGCHandleStoreFFI,
    pub DestroyHandleStore:
        extern "C" fn(this: *mut IGCHandleManagerFFI, store: *mut IGCHandleStoreFFI),
    pub CreateGlobalHandleOfType: extern "C" fn(
        this: *mut IGCHandleManagerFFI,
        object: *mut Object,
        type_: HandleType,
    ) -> OBJECTHANDLE,
    pub CreateDuplicateHandle:
        extern "C" fn(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE) -> OBJECTHANDLE,
    pub DestroyHandleOfType:
        extern "C" fn(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE, type_: HandleType),
    pub DestroyHandleOfUnknownType:
        extern "C" fn(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE),
    pub SetExtraInfoForHandle: extern "C" fn(
        this: *mut IGCHandleManagerFFI,
        handle: OBJECTHANDLE,
        type_: HandleType,
        pExtraInfo: *mut c_void,
    ),
    pub GetExtraInfoFromHandle:
        extern "C" fn(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE) -> *mut c_void,
    pub StoreObjectInHandle:
        extern "C" fn(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE, object: *mut Object),
    pub StoreObjectInHandleIfNull: extern "C" fn(
        this: *mut IGCHandleManagerFFI,
        handle: OBJECTHANDLE,
        object: *mut Object,
    ) -> bool,
    pub SetDependentHandleSecondary:
        extern "C" fn(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE, object: *mut Object),
    pub GetDependentHandleSecondary:
        extern "C" fn(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE) -> *mut Object,
    pub InterlockedCompareExchangeObjectInHandle: extern "C" fn(
        this: *mut IGCHandleManagerFFI,
        handle: OBJECTHANDLE,
        object: *mut Object,
        comparandObject: *mut Object,
    ) -> *mut Object,
    pub HandleFetchType:
        extern "C" fn(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE) -> HandleType,
    pub TraceRefCountedHandles: extern "C" fn(
        this: *mut IGCHandleManagerFFI,
        callback: HANDLESCANPROC,
        param1: usize,
        param2: usize,
    ),
}

// --- IGCHeap ---
#[repr(C)]
pub struct IGCHeapFFI {
    pub vtable: *const IGCHeapVTable,
}

pub type ConfigurationValueFunc = Option<
    extern "C" fn(
        context: *mut c_void,
        name: *mut c_void,
        public_key: *mut c_void,
        type_: GCConfigurationType,
        data: i64,
    ),
>;

#[repr(C)]
pub struct IGCHeapVTable {
    // Hosting APIs
    pub IsValidSegmentSize: extern "C" fn(this: *mut IGCHeapFFI, size: usize) -> bool,
    pub IsValidGen0MaxSize: extern "C" fn(this: *mut IGCHeapFFI, size: usize) -> bool,
    pub GetValidSegmentSize: extern "C" fn(this: *mut IGCHeapFFI, large_seg: bool) -> usize,
    pub SetReservedVMLimit: extern "C" fn(this: *mut IGCHeapFFI, vmlimit: usize),

    // Concurrent GC
    pub WaitUntilConcurrentGCComplete: extern "C" fn(this: *mut IGCHeapFFI),
    pub IsConcurrentGCInProgress: extern "C" fn(this: *mut IGCHeapFFI) -> bool,
    pub TemporaryEnableConcurrentGC: extern "C" fn(this: *mut IGCHeapFFI),
    pub TemporaryDisableConcurrentGC: extern "C" fn(this: *mut IGCHeapFFI),
    pub IsConcurrentGCEnabled: extern "C" fn(this: *mut IGCHeapFFI) -> bool,
    pub WaitUntilConcurrentGCCompleteAsync:
        extern "C" fn(this: *mut IGCHeapFFI, millisecondsTimeout: c_int) -> HRESULT,

    // Finalization
    pub GetNumberOfFinalizable: extern "C" fn(this: *mut IGCHeapFFI) -> usize,
    pub GetNextFinalizable: extern "C" fn(this: *mut IGCHeapFFI) -> *mut Object,

    // BCL APIs
    pub GetMemoryInfo: extern "C" fn(
        this: *mut IGCHeapFFI,
        highMemLoadThresholdBytes: *mut u64,
        totalAvailableMemoryBytes: *mut u64,
        lastRecordedMemLoadBytes: *mut u64,
        lastRecordedHeapSizeBytes: *mut u64,
        lastRecordedFragmentationBytes: *mut u64,
        totalCommittedBytes: *mut u64,
        promotedBytes: *mut u64,
        pinnedObjectCount: *mut u64,
        finalizationPendingCount: *mut u64,
        index: *mut u64,
        generation: *mut u32,
        pauseTimePct: *mut u32,
        isCompaction: *mut bool,
        isConcurrent: *mut bool,
        genInfoRaw: *mut u64,
        pauseInfoRaw: *mut u64,
        kind: c_int,
    ),
    pub GetMemoryLoad: extern "C" fn(this: *mut IGCHeapFFI) -> u32,
    pub GetGcLatencyMode: extern "C" fn(this: *mut IGCHeapFFI) -> c_int,
    pub SetGcLatencyMode: extern "C" fn(this: *mut IGCHeapFFI, newLatencyMode: c_int) -> c_int,
    pub GetLOHCompactionMode: extern "C" fn(this: *mut IGCHeapFFI) -> c_int,
    pub SetLOHCompactionMode: extern "C" fn(this: *mut IGCHeapFFI, newLOHCompactionMode: c_int),
    pub RegisterForFullGCNotification:
        extern "C" fn(this: *mut IGCHeapFFI, gen2Percentage: u32, lohPercentage: u32) -> bool,
    pub CancelFullGCNotification: extern "C" fn(this: *mut IGCHeapFFI) -> bool,
    pub WaitForFullGCApproach:
        extern "C" fn(this: *mut IGCHeapFFI, millisecondsTimeout: c_int) -> c_int,
    pub WaitForFullGCComplete:
        extern "C" fn(this: *mut IGCHeapFFI, millisecondsTimeout: c_int) -> c_int,
    pub WhichGeneration: extern "C" fn(this: *mut IGCHeapFFI, obj: *mut Object) -> c_uint,
    pub CollectionCount:
        extern "C" fn(this: *mut IGCHeapFFI, generation: c_int, get_bgc_fgc_coutn: c_int) -> c_int,
    pub StartNoGCRegion: extern "C" fn(
        this: *mut IGCHeapFFI,
        totalSize: u64,
        lohSizeKnown: bool,
        lohSize: u64,
        disallowFullBlockingGC: bool,
    ) -> c_int,
    pub EndNoGCRegion: extern "C" fn(this: *mut IGCHeapFFI) -> c_int,
    pub GetTotalBytesInUse: extern "C" fn(this: *mut IGCHeapFFI) -> usize,
    pub GetTotalAllocatedBytes: extern "C" fn(this: *mut IGCHeapFFI) -> u64,
    pub GarbageCollect: extern "C" fn(
        this: *mut IGCHeapFFI,
        generation: c_int,
        low_memory_p: bool,
        mode: c_int,
    ) -> HRESULT,
    pub GetMaxGeneration: extern "C" fn(this: *mut IGCHeapFFI) -> c_uint,
    pub SetFinalizationRun: extern "C" fn(this: *mut IGCHeapFFI, obj: *mut Object),
    pub RegisterForFinalization:
        extern "C" fn(this: *mut IGCHeapFFI, gen: c_int, obj: *mut Object) -> bool,
    pub GetLastGCPercentTimeInGC: extern "C" fn(this: *mut IGCHeapFFI) -> c_int,
    pub GetLastGCGenerationSize: extern "C" fn(this: *mut IGCHeapFFI, gen: c_int) -> usize,

    // Misc VM routines
    pub Initialize: extern "C" fn(this: *mut IGCHeapFFI) -> HRESULT,
    pub IsPromoted: extern "C" fn(this: *mut IGCHeapFFI, object: *mut Object) -> bool,
    pub IsHeapPointer:
        extern "C" fn(this: *mut IGCHeapFFI, object: *mut c_void, small_heap_only: bool) -> bool,
    pub GetCondemnedGeneration: extern "C" fn(this: *mut IGCHeapFFI) -> c_uint,
    pub IsGCInProgressHelper: extern "C" fn(this: *mut IGCHeapFFI, bConsiderGCStart: bool) -> bool,
    pub GetGcCount: extern "C" fn(this: *mut IGCHeapFFI) -> c_uint,
    pub IsThreadUsingAllocationContextHeap: extern "C" fn(
        this: *mut IGCHeapFFI,
        acontext: *mut gc_alloc_context,
        thread_number: c_int,
    ) -> bool,
    pub IsEphemeral: extern "C" fn(this: *mut IGCHeapFFI, object: *mut Object) -> bool,
    pub WaitUntilGCComplete: extern "C" fn(this: *mut IGCHeapFFI, bConsiderGCStart: bool) -> u32,
    pub FixAllocContext: extern "C" fn(
        this: *mut IGCHeapFFI,
        acontext: *mut gc_alloc_context,
        arg: *mut c_void,
        heap: *mut c_void,
    ),
    pub GetCurrentObjSize: extern "C" fn(this: *mut IGCHeapFFI) -> usize,
    pub SetGCInProgress: extern "C" fn(this: *mut IGCHeapFFI, fInProgress: bool),
    pub RuntimeStructuresValid: extern "C" fn(this: *mut IGCHeapFFI) -> bool,
    pub SetSuspensionPending: extern "C" fn(this: *mut IGCHeapFFI, fSuspensionPending: bool),
    pub SetYieldProcessorScalingFactor:
        extern "C" fn(this: *mut IGCHeapFFI, yieldProcessorScalingFactor: c_float),
    pub Shutdown: extern "C" fn(this: *mut IGCHeapFFI),

    // Add/RemoveMemoryPressure support
    pub GetLastGCStartTime: extern "C" fn(this: *mut IGCHeapFFI, generation: c_int) -> usize,
    pub GetLastGCDuration: extern "C" fn(this: *mut IGCHeapFFI, generation: c_int) -> usize,
    pub GetNow: extern "C" fn(this: *mut IGCHeapFFI) -> usize,

    // Allocation
    pub Alloc: extern "C" fn(
        this: *mut IGCHeapFFI,
        acontext: *mut gc_alloc_context,
        size: usize,
        flags: u32,
    ) -> *mut Object,
    pub PublishObject: extern "C" fn(this: *mut IGCHeapFFI, obj: *mut u8),
    pub SetWaitForGCEvent: extern "C" fn(this: *mut IGCHeapFFI),
    pub ResetWaitForGCEvent: extern "C" fn(this: *mut IGCHeapFFI),

    // Heap Verification
    pub IsLargeObject: extern "C" fn(this: *mut IGCHeapFFI, pObj: *mut Object) -> bool,
    pub ValidateObjectMember: extern "C" fn(this: *mut IGCHeapFFI, obj: *mut Object),
    pub NextObj: extern "C" fn(this: *mut IGCHeapFFI, object: *mut Object) -> *mut Object,
    pub GetContainingObject: extern "C" fn(
        this: *mut IGCHeapFFI,
        pInteriorPtr: *mut c_void,
        fCollectedGenOnly: bool,
    ) -> *mut Object,

    // Profiling
    pub DiagWalkObject:
        extern "C" fn(this: *mut IGCHeapFFI, obj: *mut Object, fn_: walk_fn, context: *mut c_void),
    pub DiagWalkObject2:
        extern "C" fn(this: *mut IGCHeapFFI, obj: *mut Object, fn_: walk_fn2, context: *mut c_void),
    pub DiagWalkHeap: extern "C" fn(
        this: *mut IGCHeapFFI,
        fn_: walk_fn,
        context: *mut c_void,
        gen_number: c_int,
        walk_large_object_heap_p: bool,
    ),
    pub DiagWalkSurvivorsWithType: extern "C" fn(
        this: *mut IGCHeapFFI,
        gc_context: *mut c_void,
        fn_: record_surv_fn,
        diag_context: *mut c_void,
        type_: walk_surv_type,
        gen_number: c_int,
    ),
    pub DiagWalkFinalizeQueue:
        extern "C" fn(this: *mut IGCHeapFFI, gc_context: *mut c_void, fn_: fq_walk_fn),
    pub DiagScanFinalizeQueue:
        extern "C" fn(this: *mut IGCHeapFFI, fn_: fq_scan_fn, context: *mut ScanContext),
    pub DiagScanHandles: extern "C" fn(
        this: *mut IGCHeapFFI,
        fn_: handle_scan_fn,
        gen_number: c_int,
        context: *mut ScanContext,
    ),
    pub DiagScanDependentHandles: extern "C" fn(
        this: *mut IGCHeapFFI,
        fn_: handle_scan_fn,
        gen_number: c_int,
        context: *mut ScanContext,
    ),
    pub DiagDescrGenerations:
        extern "C" fn(this: *mut IGCHeapFFI, fn_: gen_walk_fn, context: *mut c_void),
    pub DiagTraceGCSegments: extern "C" fn(this: *mut IGCHeapFFI),
    pub DiagGetGCSettings: extern "C" fn(this: *mut IGCHeapFFI, settings: *mut EtwGCSettingsInfo),

    // GC Stress
    pub StressHeap: extern "C" fn(this: *mut IGCHeapFFI, acontext: *mut gc_alloc_context) -> bool,

    // Frozen Objects
    pub RegisterFrozenSegment:
        extern "C" fn(this: *mut IGCHeapFFI, pseginfo: *mut segment_info) -> segment_handle,
    pub UnregisterFrozenSegment: extern "C" fn(this: *mut IGCHeapFFI, seg: segment_handle),
    pub IsInFrozenSegment: extern "C" fn(this: *mut IGCHeapFFI, object: *mut Object) -> bool,

    // Event Control
    pub ControlEvents:
        extern "C" fn(this: *mut IGCHeapFFI, keyword: GCEventKeyword, level: GCEventLevel),
    pub ControlPrivateEvents:
        extern "C" fn(this: *mut IGCHeapFFI, keyword: GCEventKeyword, level: GCEventLevel),
    pub GetGenerationWithRange: extern "C" fn(
        this: *mut IGCHeapFFI,
        object: *mut Object,
        ppStart: *mut *mut u8,
        ppAllocated: *mut *mut u8,
        ppReserved: *mut *mut u8,
    ) -> c_uint,

    // New additions
    pub GetTotalPauseDuration: extern "C" fn(this: *mut IGCHeapFFI) -> i64,
    pub EnumerateConfigurationValues: extern "C" fn(
        this: *mut IGCHeapFFI,
        context: *mut c_void,
        configurationValueFunc: ConfigurationValueFunc,
    ),
    pub UpdateFrozenSegment: extern "C" fn(
        this: *mut IGCHeapFFI,
        seg: segment_handle,
        allocated: *mut u8,
        committed: *mut u8,
    ),
    pub RefreshMemoryLimit: extern "C" fn(this: *mut IGCHeapFFI) -> c_int,
    pub EnableNoGCRegionCallback: extern "C" fn(
        this: *mut IGCHeapFFI,
        callback: *mut NoGCRegionCallbackFinalizerWorkItem,
        callback_threshold: u64,
    ) -> enable_no_gc_region_callback_status,
    pub GetExtraWorkForFinalization: extern "C" fn(this: *mut IGCHeapFFI) -> *mut FinalizerWorkItem,
    pub GetGenerationBudget: extern "C" fn(this: *mut IGCHeapFFI, generation: c_int) -> u64,
    pub GetLOHThreshold: extern "C" fn(this: *mut IGCHeapFFI) -> usize,
    pub DiagWalkHeapWithACHandling: extern "C" fn(
        this: *mut IGCHeapFFI,
        fn_: walk_fn,
        context: *mut c_void,
        gen_number: c_int,
        walk_large_object_heap_p: bool,
    ),
}

// --- GC Loader Entrypoints ---

// These are the functions your Rust dylib must export for the .NET runtime to find and initialize your GC.
// The calling convention `LOCALGC_CALLCONV` is `__cdecl` on x86, `C` otherwise.
#[cfg(target_arch = "x86")]
pub type GC_VersionInfoFunction = Option<extern "cdecl" fn(version_info: *mut VersionInfo)>;
#[cfg(not(target_arch = "x86"))]
pub type GC_VersionInfoFunction = Option<extern "C" fn(version_info: *mut VersionInfo)>;

#[cfg(target_arch = "x86")]
pub type GC_InitializeFunction = Option<
    extern "cdecl" fn(
        clr_to_gc: *mut IGCToCLR,
        gc_heap: *mut *mut IGCHeapFFI,
        gc_handle_manager: *mut *mut IGCHandleManagerFFI,
        dac_vars: *mut GcDacVars,
    ) -> HRESULT,
>;
#[cfg(not(target_arch = "x86"))]
pub type GC_InitializeFunction = Option<
    extern "C" fn(
        clr_to_gc: *mut IGCToCLR,
        gc_heap: *mut *mut IGCHeapFFI,
        gc_handle_manager: *mut *mut IGCHandleManagerFFI,
        dac_vars: *mut GcDacVars,
    ) -> HRESULT,
>;
