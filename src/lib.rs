// lib.rs

#![allow(non_snake_case, unused_variables, dead_code)]

// A helper for printing debug messages, like the article's `Write` method
macro_rules! log {
    ($($arg:tt)*) => {
        println!("[MyRustGC] {}", format!($($arg)*))
    };
}

// Import our FFI definitions
mod gc_handle_manager;
mod gc_handle_store;
mod gc_heap;
mod interfaces;

use interfaces::*;

use crate::gc_heap::MyGCHeap;
use std::ffi::{c_char, c_uint, c_void};
use std::os::raw::c_int;
use std::ptr::null_mut;

// --- IGCToCLR (Interface provided by the EE to the GC) ---
#[repr(C)]
pub struct IGCToCLRVTable {
    pub SuspendEE: extern "C" fn(this: *mut IGCToCLR, reason: SUSPEND_REASON),
    pub RestartEE: extern "C" fn(this: *mut IGCToCLR, bFinishedGC: bool),
    pub GcScanRoots: extern "C" fn(
        this: *mut IGCToCLR,
        fn_ptr: promote_func,
        condemned: c_int,
        max_gen: c_int,
        sc: *mut ScanContext,
    ),
    pub GcStartWork: extern "C" fn(this: *mut IGCToCLR, condemned: c_int, max_gen: c_int),
    pub BeforeGcScanRoots:
        extern "C" fn(this: *mut IGCToCLR, condemned: c_int, is_bgc: bool, is_concurrent: bool),
    pub AfterGcScanRoots:
        extern "C" fn(this: *mut IGCToCLR, condemned: c_int, max_gen: c_int, sc: *mut ScanContext),
    pub GcDone: extern "C" fn(this: *mut IGCToCLR, condemned: c_int),
    pub RefCountedHandleCallbacks: extern "C" fn(this: *mut IGCToCLR, pObject: *mut Object) -> bool,
    pub SyncBlockCacheWeakPtrScan:
        extern "C" fn(this: *mut IGCToCLR, scanProc: HANDLESCANPROC, lp1: usize, lp2: usize),
    pub SyncBlockCacheDemote: extern "C" fn(this: *mut IGCToCLR, max_gen: c_int),
    pub SyncBlockCachePromotionsGranted: extern "C" fn(this: *mut IGCToCLR, max_gen: c_int),
    pub GetActiveSyncBlockCount: extern "C" fn(this: *mut IGCToCLR) -> u32,
    pub IsPreemptiveGCDisabled: extern "C" fn(this: *mut IGCToCLR) -> bool,
    pub EnablePreemptiveGC: extern "C" fn(this: *mut IGCToCLR) -> bool,
    pub DisablePreemptiveGC: extern "C" fn(this: *mut IGCToCLR),
    pub GetThread: extern "C" fn(this: *mut IGCToCLR) -> *mut Thread,
    pub GetAllocContext: extern "C" fn(this: *mut IGCToCLR) -> *mut gc_alloc_context,
    pub GcEnumAllocContexts: extern "C" fn(
        this: *mut IGCToCLR,
        fn_ptr: enum_alloc_context_func,
        param: *mut std::ffi::c_void,
    ),
    pub GetLoaderAllocatorObjectForGC:
        extern "C" fn(this: *mut IGCToCLR, pObject: *mut Object) -> *mut u8,
    pub CreateThread: extern "C" fn(
        this: *mut IGCToCLR,
        threadStart: extern "C" fn(*mut std::ffi::c_void),
        arg: *mut std::ffi::c_void,
        is_suspendable: bool,
        name: *const c_char,
    ) -> bool,
    pub DiagGCStart: extern "C" fn(this: *mut IGCToCLR, gen: c_int, isInduced: bool),
    pub DiagUpdateGenerationBounds: extern "C" fn(this: *mut IGCToCLR),
    pub DiagGCEnd: extern "C" fn(
        this: *mut IGCToCLR,
        index: usize,
        gen: c_int,
        reason: c_int,
        fConcurrent: bool,
    ),
    pub DiagWalkFReachableObjects:
        extern "C" fn(this: *mut IGCToCLR, gcContext: *mut std::ffi::c_void),
    pub DiagWalkSurvivors:
        extern "C" fn(this: *mut IGCToCLR, gcContext: *mut std::ffi::c_void, fCompacting: bool),
    pub DiagWalkUOHSurvivors:
        extern "C" fn(this: *mut IGCToCLR, gcContext: *mut std::ffi::c_void, gen: c_int),
    pub DiagWalkBGCSurvivors: extern "C" fn(this: *mut IGCToCLR, gcContext: *mut std::ffi::c_void),
    pub StompWriteBarrier: extern "C" fn(this: *mut IGCToCLR, args: *const WriteBarrierParameters),
    pub EnableFinalization: extern "C" fn(this: *mut IGCToCLR, gcHasWorkForFinalizerThread: bool),
    pub HandleFatalError: extern "C" fn(this: *mut IGCToCLR, exitCode: u32),
    pub EagerFinalized: extern "C" fn(this: *mut IGCToCLR, obj: *mut Object) -> bool,
    pub GetFreeObjectMethodTable: extern "C" fn(this: *mut IGCToCLR) -> *mut MethodTable,
    pub GetBooleanConfigValue: extern "C" fn(
        this: *mut IGCToCLR,
        privateKey: *const c_char,
        publicKey: *const c_char,
        value: *mut bool,
    ) -> bool,
    pub GetIntConfigValue: extern "C" fn(
        this: *mut IGCToCLR,
        privateKey: *const c_char,
        publicKey: *const c_char,
        value: *mut i64,
    ) -> bool,
    pub GetStringConfigValue: extern "C" fn(
        this: *mut IGCToCLR,
        privateKey: *const c_char,
        publicKey: *const c_char,
        value: *mut *const c_char,
    ) -> bool,
    pub FreeStringConfigValue: extern "C" fn(this: *mut IGCToCLR, value: *const c_char),
    pub IsGCThread: extern "C" fn(this: *mut IGCToCLR) -> bool,
    pub WasCurrentThreadCreatedByGC: extern "C" fn(this: *mut IGCToCLR) -> bool,
    pub WalkAsyncPinnedForPromotion: extern "C" fn(
        this: *mut IGCToCLR,
        object: *mut Object,
        sc: *mut ScanContext,
        callback: promote_func,
    ),
    pub WalkAsyncPinned: extern "C" fn(
        this: *mut IGCToCLR,
        object: *mut Object,
        context: *mut std::ffi::c_void,
        callback: extern "C" fn(*mut Object, *mut Object, *mut std::ffi::c_void),
    ),
    pub EventSink: extern "C" fn(this: *mut IGCToCLR) -> *mut IGCToCLREventSink,
    pub GetTotalNumSizedRefHandles: extern "C" fn(this: *mut IGCToCLR) -> u32,
    pub AnalyzeSurvivorsRequested:
        extern "C" fn(this: *mut IGCToCLR, condemnedGeneration: c_int) -> bool,
    pub AnalyzeSurvivorsFinished: extern "C" fn(
        this: *mut IGCToCLR,
        gcIndex: usize,
        condemnedGeneration: c_int,
        promoted_bytes: u64,
        reportGenerationBounds: extern "C" fn(),
    ),
    pub VerifySyncTableEntry: extern "C" fn(this: *mut IGCToCLR),
    pub UpdateGCEventStatus: extern "C" fn(
        this: *mut IGCToCLR,
        publicLevel: c_int,
        publicKeywords: c_int,
        privateLEvel: c_int,
        privateKeywords: c_int,
    ),
    pub LogStressMsg:
        extern "C" fn(this: *mut IGCToCLR, level: u32, facility: u32, msg: *const StressLogMsg),
    pub GetCurrentProcessCpuCount: extern "C" fn(this: *mut IGCToCLR) -> u32,
    pub DiagAddNewRegion: extern "C" fn(
        this: *mut IGCToCLR,
        generation: c_int,
        rangeStart: *mut u8,
        rangeEnd: *mut u8,
        rangeEndReserved: *mut u8,
    ),
    pub LogErrorToHost: extern "C" fn(this: *mut IGCToCLR, message: *const c_char),
    pub GetThreadOSThreadId: extern "C" fn(this: *mut IGCToCLR, thread: *mut Thread) -> u64,
    pub TriggerClientBridgeProcessing:
        extern "C" fn(this: *mut IGCToCLR, args: *mut MarkCrossReferencesArgs),
}

pub enum MethodTable {}
pub enum IGCToCLREventSink {}
pub enum MarkCrossReferencesArgs {}
pub enum StressLogMsg {}

impl IGCToCLR {
    // Helper to safely call a VTable method.
    pub unsafe fn get_boolean_config_value(&self, name: &[u8], public_name: &[u8]) -> Option<bool> {
        let mut val = false;
        let success = ((*self.vtable).GetBooleanConfigValue)(
            self as *const _ as *mut _,
            name.as_ptr() as *const c_char,
            public_name.as_ptr() as *const c_char,
            &mut val,
        );
        if success {
            Some(val)
        } else {
            None
        }
    }

    pub unsafe fn stomp_write_barrier(&self, params: &WriteBarrierParameters) {
        ((*self.vtable).StompWriteBarrier)(self as *const _ as *mut _, params);
    }
}

// --- The GC Entry Point: GC_Initialize ---

#[no_mangle]
pub extern "C" fn GC_Initialize(
    clr_to_gc: *mut IGCToCLR,
    gc_heap: *mut *mut IGCHeapFFI,
    gc_handle_manager: *mut *mut IGCHandleManagerFFI,
    dac_vars: *mut GcDacVars,
) -> HRESULT {
    log!("GC_Initialize called from the runtime!");

    // Check if server GC is enabled, which our simple GC doesn't support.
    unsafe {
        let is_server_gc =
            (*clr_to_gc).get_boolean_config_value(b"System.GC.Server\0", b"gcServer\0");
        if is_server_gc == Some(true) {
            log!("ERROR: This custom GC does not support Server GC mode.");
            log!("Set environment variable DOTNET_gcServer=0");
            return -1; // E_FAIL
        }
    }

    // Create our main GC heap object. It owns the handle manager.
    let my_gc_heap = Box::new(MyGCHeap::new(clr_to_gc));

    // The runtime will own the memory from now on. We must not drop the box.
    let heap_ptr = Box::into_raw(my_gc_heap);

    unsafe {
        *gc_heap = &mut (*heap_ptr).ffi;
        *gc_handle_manager = &mut (*heap_ptr).handle_manager.ffi;
        // Add verification logging
        log!("GC_Initialize: Set gc_heap to {:p}", *gc_heap);
        log!(
            "GC_Initialize: Set gc_handle_manager to {:p}",
            *gc_handle_manager
        );

        let dac = &mut *dac_vars;

        log!("GC_Initialize: Set dac to {:?}", dac.generation_size);
        log!("GC_Initialize: Set dac to {:?}", dac.major_version_number);
        log!("GC_Initialize: Set dac to {:?}", dac.minor_version_number);
        log!("GC_Initialize: Set dac to {:?}", dac.total_generation_count);

        // Verify the vtable is accessible
        let heap_vtable = (*(*gc_heap)).vtable;
        log!("GC_Initialize: Heap vtable at {:p}", heap_vtable);
    }
    log!("Finished initialization");

    0 // S_OK
}

#[no_mangle]
pub unsafe extern "C" fn GC_VersionInfo(version_info: *mut VersionInfo) {
    if version_info.is_null() {
        return;
    }
    let clr_version = &*version_info;
    println!(
        "Rust GC: GC_VersionInfo called with CLR version {}.{}.{}",
        clr_version.major_version, clr_version.minor_version, clr_version.build_version
    );

    let our_version = &mut *version_info;
    our_version.major_version = GC_INTERFACE_MAJOR_VERSION;
    our_version.minor_version = GC_INTERFACE_MINOR_VERSION;
}

// --- VTable Shim Functions & Static Definitions ---

// Helper macro to create no-op shims for unimplemented functions.
macro_rules! unimplemented_shim {
    ($name:ident, $ret_type:ty, $($arg:ident: $type:ty),*) => {
        extern "C" fn $name(this: *mut c_void, $($arg: $type),*) -> $ret_type {
            log!("Unimplemented GC method called: {}", stringify!($name));
            // Provide a default/zeroed return value.
            unsafe { std::mem::zeroed() }
        }
    };
    // Variant for void return type
    ($name:ident, $($arg:ident: $type:ty),*) => {
        extern "C" fn $name(this: *mut c_void, $($arg: $type),*) {
            log!("Unimplemented GC method called: {}", stringify!($name));
        }
    };
}
