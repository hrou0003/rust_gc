// lib.rs

#![allow(non_snake_case, unused_variables, dead_code)]

// Import our FFI definitions
mod interfaces;
use interfaces::*;

use std::alloc::{alloc_zeroed, Layout};
use std::ffi::{c_float, c_uint, c_void};
use std::os::raw::c_int;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicIsize, Ordering};

// A helper for printing debug messages, like the article's `Write` method
macro_rules! log {
    ($($arg:tt)*) => {
        println!("[MyRustGC] {}", format!($($arg)*))
    };
}

// --- Handle Management Implementation ---
// Add this to gc_interface.rs

// --- IGCToCLR (Interface provided by the EE to the GC) ---
#[repr(C)]
pub struct IGCToCLRVTable {
    // This is an incomplete VTable, we only add the methods we need.
    // The real VTable has many more functions. The offsets must be correct.
    // To be safe, we list dummy entries for unknown methods.
    _dummy0: [usize; 2], // Two initial methods we don't use
    pub SuspendEE: extern "C" fn(this: *mut IGCToCLR, reason: SUSPEND_REASON) -> HRESULT,
    pub ResumeEE: extern "C" fn(this: *mut IGCToCLR, completed: bool) -> HRESULT,
    pub GcScanRoots: extern "C" fn(
        this: *mut IGCToCLR,
        promote_fn: promote_func,
        condemned_generation_number: c_int,
        sc: *mut ScanContext,
    ),
    pub RestartEE: extern "C" fn(this: *mut IGCToCLR, completed: bool),
    _dummy1: [usize; 11], // more unused methods
    pub GetBooleanConfigValue: extern "C" fn(
        this: *mut IGCToCLR,
        name: *const u8,
        public_name: *const u8,
        out_val: *mut bool,
    ) -> bool,
    _dummy2: [usize; 7], // more unused methods
    pub StompWriteBarrier:
        extern "C" fn(this: *mut IGCToCLR, params: *const WriteBarrierParameters),
    // ... and many more we don't need for this example
}

#[repr(C)]
pub struct IGCToCLR {
    pub vtable: *const IGCToCLRVTable,
}

impl IGCToCLR {
    // Helper to safely call a VTable method.
    pub unsafe fn get_boolean_config_value(&self, name: &[u8], public_name: &[u8]) -> Option<bool> {
        let mut val = false;
        let success = ((*self.vtable).GetBooleanConfigValue)(
            self as *const _ as *mut _,
            name.as_ptr(),
            public_name.as_ptr(),
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

const MAX_HANDLES: usize = 65535; // Match C# implementation

/// Simple handle store using pointer array like the C# implementation
#[repr(C)]
struct MyGCHandleStore {
    // The FFI interface must be the first field for pointer casting to work.
    ffi: IGCHandleStoreFFI,
    // Simple array of object pointers, matching C# nint* _store
    store: *mut *mut Object,
    handle_count: AtomicIsize,
}

impl MyGCHandleStore {
    fn new() -> Self {
        Self {
            ffi: IGCHandleStoreFFI {
                vtable: &GCHANDLESTORE_VTABLE,
            },
            store: std::ptr::null_mut(),
            handle_count: AtomicIsize::new(0),
        }
    }

    // Implementation matching C# CreateHandleOfType
    fn create_handle_of_type_impl(
        &mut self,
        object: *mut Object,
        type_: HandleType,
    ) -> OBJECTHANDLE {
        log!("CreateHandleOfType {:?} for {:p}", type_, object);

        let handle = self.get_next_available_handle();
        unsafe {
            // Set the object pointer in our store
            let handle_ptr = handle as *mut *mut Object;
            *handle_ptr = object;
        }

        log!("Returning {:p}", handle);
        handle
    }

    // The actual implementation of CreateHandleWithExtraInfo
    fn create_handle_with_extra_info_impl(
        &mut self,
        object: *mut Object,
        type_: HandleType,
        extra_info: *mut c_void,
    ) -> OBJECTHANDLE {
        log!("GCHandleStore CreateHandleWithExtraInfo");
        self.get_next_available_handle()
    }

    // Match C# GetNextAvailableHandle implementation
    fn get_next_available_handle(&mut self) -> OBJECTHANDLE {
        let index = self.handle_count.fetch_add(1, Ordering::SeqCst);
        if index >= MAX_HANDLES as isize {
            panic!("Too many handles! Limit is {}.", MAX_HANDLES);
        }

        unsafe {
            // Return pointer to the slot in our array, matching C#: (nint)(_store + _handleCount)
            let handle_ptr = self.store.add(index as usize);
            handle_ptr as OBJECTHANDLE
        }
    }

    // The actual implementation of ContainsHandle
    fn contains_handle_impl(&self, handle: OBJECTHANDLE) -> bool {
        log!("GCHandleStore ContainsHandle");
        let handle_ptr = handle as *const *mut Object;
        let start = self.store as *const *mut Object;
        let count = self.handle_count.load(Ordering::SeqCst) as usize;
        let end = unsafe { start.add(count) };
        handle_ptr >= start && handle_ptr < end
    }

    // Match C# DumpHandles implementation
    fn dump_handles_impl(&self) {
        log!("GCHandleStore DumpHandles");

        let count = self.handle_count.load(Ordering::SeqCst) as usize;
        for i in 0..count {
            unsafe {
                let target = *self.store.add(i);
                // For now, just log the pointer like the C# version without DAC manager
                log!("Handle {} - {:p}", i, target);
            }
        }
    }

    // Add uproot implementation to match C# interface
    fn uproot_impl(&mut self) {
        log!("GCHandleStore Uproot");
    }
}

// --- GCHandleManager Implementation ---

#[repr(C)]
struct MyGCHandleManager {
    ffi: IGCHandleManagerFFI,
    store: Box<MyGCHandleStore>,
}

impl MyGCHandleManager {
    fn new() -> Self {
        Self {
            ffi: IGCHandleManagerFFI {
                vtable: &GCHANDLEMANAGER_VTABLE,
            },
            store: Box::new(MyGCHandleStore::new()),
        }
    }

    pub fn create_global_handle_of_type(
        &mut self,
        object: *mut Object,
        type_: HandleType,
    ) -> Result<OBJECTHANDLE, &'static str> {
        Ok(self.store.create_handle_of_type_impl(object, type_))
    }
}

// --- GCHeap Implementation ---

#[repr(C)]
struct MyGCHeap {
    ffi: IGCHeapFFI,
    clr_to_gc: *mut IGCToCLR,
    handle_manager: Box<MyGCHandleManager>,
}

impl MyGCHeap {
    fn new(clr_to_gc: *mut IGCToCLR) -> Self {
        Self {
            ffi: IGCHeapFFI {
                vtable: &GCHEAP_VTABLE,
            },
            clr_to_gc,
            handle_manager: Box::new(MyGCHandleManager::new()),
        }
    }

    // The actual implementation of Initialize
    fn initialize_impl(&mut self) -> HRESULT {
        log!("[MyGCHeap] Initialize called");

        // Allocate the handle store now that the runtime is ready.
        let layout =
            std::alloc::Layout::array::<*mut crate::interfaces::Object>(MAX_HANDLES).unwrap();
        let store_ptr =
            unsafe { std::alloc::alloc_zeroed(layout) as *mut *mut crate::interfaces::Object };
        if store_ptr.is_null() {
            panic!("Failed to allocate memory for handle store");
        }
        self.handle_manager.store.store = store_ptr;
        log!("[MyGCHeap] GCHandleStore allocated at: {:p}", store_ptr);

        // Set up write barrier parameters to match C# implementation, effectively disabling it.
        let params = WriteBarrierParameters {
            operation: WriteBarrierOp::Initialize,
            is_runtime_suspended: true,
            requires_upper_bounds_check: false, // Ignored for Initialize operation
            card_table: std::ptr::null_mut(),
            card_bundle_table: std::ptr::null_mut(),
            lowest_address: std::ptr::null_mut(),
            highest_address: std::ptr::null_mut(),
            // C# sets ephemeral_low to ~0 (all bits set) to disable write barriers
            ephemeral_low: !0_usize as *mut u8, // Equivalent to (byte*)(~0) in C#
            ephemeral_high: std::ptr::null_mut(),
            write_watch_table: std::ptr::null_mut(),
            region_to_generation_table: std::ptr::null_mut(),
            region_shr: 0,
            region_use_bitwise_write_barrier: false,
        };

        unsafe {
            (*self.clr_to_gc).stomp_write_barrier(&params);
        }

        log!("GCHeap initialization completed successfully");
        0 // S_OK
    }

    // The actual implementation of Alloc
    fn alloc_impl(
        &mut self,
        acontext: &mut gc_alloc_context,
        size: usize,
        flags: u32,
    ) -> *mut Object {
        log!(
            "Alloc: {} (alloc context: {:p}, start: {:p}, size: {:#x}, limit: {:p})",
            size,
            acontext,
            acontext.alloc_ptr as *const u8,
            size,
            acontext.alloc_limit as *const u8
        );

        let result = acontext.alloc_ptr;
        let advance = unsafe { result.add(size) };

        if advance <= acontext.alloc_limit {
            // Fast path: current allocation context has enough space.
            acontext.alloc_ptr = advance;
            return result as *mut Object;
        }

        // Slow path: need to get a new chunk of memory for the context.
        // Use C# implementation strategy: 16MB growth with 24-byte begin gap
        const BEGIN_GAP: usize = 24;
        const GROWTH_SIZE: usize = 16 * 1024 * 1024; // 16MB

        let actual_growth_size = size.max(GROWTH_SIZE);
        let layout = Layout::from_size_align(actual_growth_size, 8).unwrap();
        let new_pages = unsafe { alloc_zeroed(layout) };

        if new_pages.is_null() {
            log!(
                "Out of memory: failed to allocate {} bytes",
                actual_growth_size
            );
            return std::ptr::null_mut(); // Out of memory
        }

        // The allocation starts after the begin gap
        let allocation_start = unsafe { new_pages.add(BEGIN_GAP) };
        acontext.alloc_ptr = unsafe { allocation_start.add(size) };
        acontext.alloc_limit = unsafe { new_pages.add(actual_growth_size) };

        log!(
            "Allocated new chunk: {:p}, allocation start: {:p}, new limit: {:p}",
            new_pages,
            allocation_start,
            acontext.alloc_limit as *const u8
        );

        allocation_start as *mut Object
    }

    fn garbage_collect_impl(&mut self, generation: i32) -> HRESULT {
        log!("GarbageCollect called for generation {}", generation);
        self.handle_manager.store.dump_handles_impl();
        0 // S_OK
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
    }

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
    our_version.major_version = 5;
    our_version.minor_version = 3;
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

// --- IGCHandleStore VTable ---

extern "C" fn store_uproot(this: *mut IGCHandleStoreFFI) {
    let store = unsafe { &mut *(this as *mut MyGCHandleStore) };
    store.uproot_impl();
}
extern "C" fn store_contains_handle(this: *mut IGCHandleStoreFFI, handle: OBJECTHANDLE) -> bool {
    let store = unsafe { &mut *(this as *mut MyGCHandleStore) };
    store.contains_handle_impl(handle)
}
extern "C" fn store_create_handle(
    this: *mut IGCHandleStoreFFI,
    object: *mut Object,
    type_: HandleType,
) -> OBJECTHANDLE {
    let store = unsafe { &mut *(this as *mut MyGCHandleStore) };
    store.create_handle_of_type_impl(object, type_)
}
extern "C" fn store_create_handle_affinitized(
    this: *mut IGCHandleStoreFFI,
    object: *mut Object,
    type_: HandleType,
    heap: c_int,
) -> OBJECTHANDLE {
    let store = unsafe { &mut *(this as *mut MyGCHandleStore) };
    store.create_handle_of_type_impl(object, type_)
}
extern "C" fn store_create_handle_with_extra(
    this: *mut IGCHandleStoreFFI,
    object: *mut Object,
    type_: HandleType,
    extra: *mut c_void,
) -> OBJECTHANDLE {
    let store = unsafe { &mut *(this as *mut MyGCHandleStore) };
    store.create_handle_with_extra_info_impl(object, type_, extra)
}
extern "C" fn store_create_dependent_handle(
    this: *mut IGCHandleStoreFFI,
    primary: *mut Object,
    secondary: *mut Object,
) -> OBJECTHANDLE {
    let store = unsafe { &mut *(this as *mut MyGCHandleStore) };
    log!("GCHandleStore CreateDependentHandle");
    store.get_next_available_handle()
}

static GCHANDLESTORE_VTABLE: IGCHandleStoreVTable = IGCHandleStoreVTable {
    Uproot: store_uproot,
    ContainsHandle: store_contains_handle,
    CreateHandleOfType: store_create_handle,
    CreateHandleOfType_HeapAffinitized: store_create_handle_affinitized,
    CreateHandleWithExtraInfo: store_create_handle_with_extra,
    CreateDependentHandle: store_create_dependent_handle,
};

// --- IGCHandleManager VTable ---

extern "C" fn mgr_initialize(this: *mut IGCHandleManagerFFI) -> bool {
    true
}
extern "C" fn mgr_shutdown(this: *mut IGCHandleManagerFFI) { /* no-op */
}
extern "C" fn mgr_get_global_handle_store(
    this: *mut IGCHandleManagerFFI,
) -> *mut IGCHandleStoreFFI {
    let manager = unsafe { &mut *(this as *mut MyGCHandleManager) };
    &mut manager.store.ffi
}

extern "C" fn mgr_create_handle_store(this: *mut IGCHandleManagerFFI) -> *mut IGCHandleStoreFFI {
    return std::ptr::null_mut();
}

extern "C" fn mgr_destroy_handle_store(
    this: *mut IGCHandleManagerFFI,
    store: *mut IGCHandleStoreFFI,
) {
}

extern "C" fn mgr_create_global_handle_of_type(
    this: *mut IGCHandleManagerFFI,
    object: *mut Object,
    type_: HandleType,
) -> OBJECTHANDLE {
    if this.is_null() || object.is_null() {
        return std::ptr::null_mut();
    }

    // TODO: Get the actual handle store and create handle
    // This should call something equivalent to _gcHandleStore.CreateHandleOfType(object, type_)
    // For now, return null to fix compilation
    let manager = unsafe { &mut *(this as *mut MyGCHandleManager) };

    match manager.create_global_handle_of_type(object, type_) {
        Ok(handle) => {
            log!("Created handle {:?} for object {:?}", handle, object);
            handle
        }
        Err(e) => {
            log!("Failed to create handle for object {:?}: {}", object, e);
            std::ptr::null_mut() as OBJECTHANDLE
        }
    }
}

extern "C" fn mgr_create_duplicate_handle(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
) -> OBJECTHANDLE {
    todo!()
}
extern "C" fn mgr_destroy_handle_of_type(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    type_: HandleType,
) {
    todo!()
}
extern "C" fn mgr_destroy_handle_of_unknown_type(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
) {
    todo!()
}
extern "C" fn mgr_set_extra_info_for_handle(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    type_: HandleType,
    pExtraInfo: *mut c_void,
) {
    todo!()
}
extern "C" fn mgr_get_extra_info_from_handle(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
) -> *mut c_void {
    todo!()
}
extern "C" fn mgr_store_object_in_handle(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    object: *mut Object,
) {
    todo!()
}
extern "C" fn mgr_store_object_in_handle_if_null(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    object: *mut Object,
) -> bool {
    todo!()
}

extern "C" fn mgr_set_dependent_handle_secondary(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    object: *mut Object,
) {
    todo!()
}
extern "C" fn mgr_get_dependent_handle_secondary(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
) -> *mut Object {
    todo!()
}
extern "C" fn mgr_interlocked_compare_exchange_object_in_handle(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    object: *mut Object,
    comparandObject: *mut Object,
) -> *mut Object {
    todo!()
}
extern "C" fn mgr_handle_fetch_type(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
) -> HandleType {
    todo!()
}
extern "C" fn mgr_trace_ref_counted_handles(
    this: *mut IGCHandleManagerFFI,
    callback: HANDLESCANPROC,
    param1: usize,
    param2: usize,
) {
    todo!()
}

extern "C" fn mgr_create_global_handle(
    this: *mut IGCHandleManagerFFI,
    object: *mut Object,
    type_: HandleType,
) -> OBJECTHANDLE {
    let manager = unsafe { &mut *(this as *mut MyGCHandleManager) };
    manager.store.create_handle_of_type_impl(object, type_)
}
extern "C" fn mgr_destroy_handle(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE) {
    /* no-op, we leak! */
}

extern "C" fn mgr_cas_object_in_handle(
    this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    object: *mut Object,
    comparand: *mut Object,
) -> *mut Object {
    let handle_ptr = handle as *mut *mut Object; // Pointer to the 'object' field
    let atomic_ptr = unsafe { &*(handle_ptr as *const AtomicIsize) };
    let result = atomic_ptr.compare_exchange(
        comparand as isize,
        object as isize,
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    match result {
        Ok(v) => v as *mut Object,
        Err(v) => v as *mut Object,
    }
}
extern "C" fn mgr_get_type(this: *mut IGCHandleManagerFFI, handle: OBJECTHANDLE) -> HandleType {
    // Since we simplified to just store object pointers like C#,
    // we can't easily determine type. Return a default.
    log!("mgr_get_type called");
    HandleType::STRONG // Default like C# might do
}

static GCHANDLEMANAGER_VTABLE: IGCHandleManagerVTable = IGCHandleManagerVTable {
    Initialize: mgr_initialize,
    Shutdown: mgr_shutdown,
    GetGlobalHandleStore: mgr_get_global_handle_store,
    CreateHandleStore: mgr_create_handle_store,
    DestroyHandleStore: mgr_destroy_handle_store,
    CreateGlobalHandleOfType: mgr_create_global_handle_of_type,
    CreateDuplicateHandle: mgr_create_duplicate_handle,
    DestroyHandleOfType: mgr_destroy_handle_of_type,
    DestroyHandleOfUnknownType: mgr_destroy_handle_of_unknown_type,
    SetExtraInfoForHandle: mgr_set_extra_info_for_handle,
    GetExtraInfoFromHandle: mgr_get_extra_info_from_handle,
    StoreObjectInHandle: mgr_store_object_in_handle,
    StoreObjectInHandleIfNull: mgr_store_object_in_handle_if_null,
    SetDependentHandleSecondary: mgr_set_dependent_handle_secondary,
    GetDependentHandleSecondary: mgr_get_dependent_handle_secondary,
    InterlockedCompareExchangeObjectInHandle: mgr_interlocked_compare_exchange_object_in_handle,
    HandleFetchType: mgr_handle_fetch_type,
    TraceRefCountedHandles: mgr_trace_ref_counted_handles, // We only have one global store
};

// --- IGCHeap VTable ---

extern "C" fn heap_initialize(this: *mut IGCHeapFFI) -> HRESULT {
    let heap = unsafe { &mut *(this as *mut MyGCHeap) };
    heap.initialize_impl()
}
extern "C" fn heap_alloc(
    this: *mut IGCHeapFFI,
    acontext: *mut gc_alloc_context,
    size: usize,
    flags: u32,
) -> *mut Object {
    let heap = unsafe { &mut *(this as *mut MyGCHeap) };
    let acontext_ref = unsafe { &mut *acontext };
    heap.alloc_impl(acontext_ref, size, flags)
}
extern "C" fn heap_garbage_collect(
    this: *mut IGCHeapFFI,
    generation: c_int,
    low_mem: bool,
    mode: c_int,
) -> HRESULT {
    let heap = unsafe { &mut *(this as *mut MyGCHeap) };
    heap.garbage_collect_impl(generation)
}

extern "C" fn is_valid_segment_size(this: *mut IGCHeapFFI, size: usize) -> bool {
    log!("IsValidSegmentSize");
    false // C# implementation returns false
}

extern "C" fn is_valid_gen0_max_size(this: *mut IGCHeapFFI, size: usize) -> bool {
    log!("IsValidGen0MaxSize");
    false // C# implementation returns false
}

extern "C" fn get_valid_segment_size(this: *mut IGCHeapFFI, large_seg: bool) -> usize {
    log!("GetValidSegmentSize");
    0 // C# implementation returns 0
}

extern "C" fn set_reserved_vm_limit(this: *mut IGCHeapFFI, vmlimit: usize) {
    log!("SetReservedVMLimit");
}

// Concurrent GC
extern "C" fn wait_until_concurrent_gc_complete(this: *mut IGCHeapFFI) {
    log!("WaitUntilConcurrentGCComplete");
}

extern "C" fn is_concurrent_gc_in_progress(this: *mut IGCHeapFFI) -> bool {
    log!("IsConcurrentGCInProgress");
    false // C# implementation returns false
}

extern "C" fn temporary_enable_concurrent_gc(this: *mut IGCHeapFFI) {
    log!("TemporaryEnableConcurrentGC");
}

extern "C" fn temporary_disable_concurrent_gc(this: *mut IGCHeapFFI) {
    log!("TemporaryDisableConcurrentGC");
}

extern "C" fn is_concurrent_gc_enabled(this: *mut IGCHeapFFI) -> bool {
    log!("IsConcurrentGCEnabled");
    false // C# implementation returns false
}

extern "C" fn wait_until_concurrent_gc_complete_async(
    this: *mut IGCHeapFFI,
    millisecondsTimeout: c_int,
) -> HRESULT {
    log!("WaitUntilConcurrentGCCompleteAsync");
    0 // S_OK
}

// Finalization
extern "C" fn get_number_of_finalizable(this: *mut IGCHeapFFI) -> usize {
    log!("GetNumberOfFinalizable");
    0 // C# implementation returns 0
}

extern "C" fn get_next_finalizable(this: *mut IGCHeapFFI) -> *mut Object {
    log!("GetNextFinalizable");
    std::ptr::null_mut() // C# implementation returns null
}

// BCL APIs
extern "C" fn get_memory_info(
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
) {
    log!("GetMemoryInfo");

    // Initialize all output parameters to zero/false as per C# implementation
    unsafe {
        if !highMemLoadThresholdBytes.is_null() {
            *highMemLoadThresholdBytes = 0;
        }
        if !totalAvailableMemoryBytes.is_null() {
            *totalAvailableMemoryBytes = 0;
        }
        if !lastRecordedMemLoadBytes.is_null() {
            *lastRecordedMemLoadBytes = 0;
        }
        if !lastRecordedHeapSizeBytes.is_null() {
            *lastRecordedHeapSizeBytes = 0;
        }
        if !lastRecordedFragmentationBytes.is_null() {
            *lastRecordedFragmentationBytes = 0;
        }
        if !totalCommittedBytes.is_null() {
            *totalCommittedBytes = 0;
        }
        if !promotedBytes.is_null() {
            *promotedBytes = 0;
        }
        if !pinnedObjectCount.is_null() {
            *pinnedObjectCount = 0;
        }
        if !finalizationPendingCount.is_null() {
            *finalizationPendingCount = 0;
        }
        if !index.is_null() {
            *index = 0;
        }
        if !generation.is_null() {
            *generation = 0;
        }
        if !pauseTimePct.is_null() {
            *pauseTimePct = 0;
        }
        if !isCompaction.is_null() {
            *isCompaction = false;
        }
        if !isConcurrent.is_null() {
            *isConcurrent = false;
        }
        if !genInfoRaw.is_null() {
            *genInfoRaw = 0;
        }
        if !pauseInfoRaw.is_null() {
            *pauseInfoRaw = 0;
        }
    }
}

extern "C" fn get_memory_load(this: *mut IGCHeapFFI) -> u32 {
    log!("GetMemoryLoad");
    0 // C# implementation returns 0
}

extern "C" fn get_gc_latency_mode(this: *mut IGCHeapFFI) -> c_int {
    log!("GetGcLatencyMode");
    0 // C# implementation returns 0
}

extern "C" fn set_gc_latency_mode(this: *mut IGCHeapFFI, newLatencyMode: c_int) -> c_int {
    log!("SetGcLatencyMode");
    0 // C# implementation returns 0
}

extern "C" fn get_loh_compaction_mode(this: *mut IGCHeapFFI) -> c_int {
    log!("GetLOHCompactionMode");
    0 // C# implementation returns 0
}

extern "C" fn set_loh_compaction_mode(this: *mut IGCHeapFFI, newLOHCompactionMode: c_int) {
    log!("SetLOHCompactionMode");
}

extern "C" fn register_for_full_gc_notification(
    this: *mut IGCHeapFFI,
    gen2Percentage: u32,
    lohPercentage: u32,
) -> bool {
    todo!()
}

extern "C" fn cancel_full_gc_notification(this: *mut IGCHeapFFI) -> bool {
    todo!()
}

extern "C" fn wait_for_full_gc_approach(
    this: *mut IGCHeapFFI,
    millisecondsTimeout: c_int,
) -> c_int {
    todo!()
}

extern "C" fn wait_for_full_gc_complete(
    this: *mut IGCHeapFFI,
    millisecondsTimeout: c_int,
) -> c_int {
    todo!()
}

extern "C" fn which_generation(this: *mut IGCHeapFFI, obj: *mut Object) -> c_uint {
    todo!()
}

extern "C" fn collection_count(
    this: *mut IGCHeapFFI,
    generation: c_int,
    get_bgc_fgc_coutn: c_int,
) -> c_int {
    todo!()
}

extern "C" fn start_no_gc_region(
    this: *mut IGCHeapFFI,
    totalSize: u64,
    lohSizeKnown: bool,
    lohSize: u64,
    disallowFullBlockingGC: bool,
) -> c_int {
    todo!()
}

extern "C" fn end_no_gc_region(this: *mut IGCHeapFFI) -> c_int {
    todo!()
}

extern "C" fn get_total_bytes_in_use(this: *mut IGCHeapFFI) -> usize {
    todo!()
}

extern "C" fn get_total_allocated_bytes(this: *mut IGCHeapFFI) -> u64 {
    todo!()
}

extern "C" fn garbage_collect(
    this: *mut IGCHeapFFI,
    generation: c_int,
    low_memory_p: bool,
    mode: c_int,
) -> HRESULT {
    todo!()
}

extern "C" fn get_max_generation(this: *mut IGCHeapFFI) -> c_uint {
    log!("GetMaxGeneration");
    2 // C# returns 2, representing generations 0, 1, and 2
}

extern "C" fn set_finalization_run(this: *mut IGCHeapFFI, obj: *mut Object) {
    todo!()
}

extern "C" fn register_for_finalization(
    this: *mut IGCHeapFFI,
    gen: c_int,
    obj: *mut Object,
) -> bool {
    todo!()
}

extern "C" fn get_last_gc_percent_time_in_gc(this: *mut IGCHeapFFI) -> c_int {
    todo!()
}

extern "C" fn get_last_gc_generation_size(this: *mut IGCHeapFFI, gen: c_int) -> usize {
    todo!()
}

// Misc VM routines
extern "C" fn initialize(this: *mut IGCHeapFFI) -> HRESULT {
    todo!()
}

extern "C" fn is_promoted(this: *mut IGCHeapFFI, object: *mut Object) -> bool {
    todo!()
}

extern "C" fn is_heap_pointer(
    this: *mut IGCHeapFFI,
    object: *mut c_void,
    small_heap_only: bool,
) -> bool {
    todo!()
}

extern "C" fn get_condemned_generation(this: *mut IGCHeapFFI) -> c_uint {
    log!("GetCondemnedGeneration");
    0
}

extern "C" fn is_gc_in_progress_helper(this: *mut IGCHeapFFI, bConsiderGCStart: bool) -> bool {
    log!("IsGCInProgressHelper");
    false
}

extern "C" fn get_gc_count(this: *mut IGCHeapFFI) -> c_uint {
    log!("GetGcCount");
    0
}

extern "C" fn is_thread_using_allocation_context_heap(
    this: *mut IGCHeapFFI,
    acontext: *mut gc_alloc_context,
    thread_number: c_int,
) -> bool {
    log!("IsThreadUsingAllocationContextHeap");
    false
}

extern "C" fn is_ephemeral(this: *mut IGCHeapFFI, object: *mut Object) -> bool {
    log!("IsEphemeral");
    false
}

extern "C" fn wait_until_gc_complete(this: *mut IGCHeapFFI, bConsiderGCStart: bool) -> u32 {
    log!("WaitUntilGCComplete");
    0
}

extern "C" fn fix_alloc_context(
    this: *mut IGCHeapFFI,
    acontext: *mut gc_alloc_context,
    arg: *mut c_void,
    heap: *mut c_void,
) {
    log!("FixAllocContext");
}

extern "C" fn get_current_obj_size(this: *mut IGCHeapFFI) -> usize {
    log!("GetCurrentObjSize");
    0
}

extern "C" fn set_gc_in_progress(this: *mut IGCHeapFFI, fInProgress: bool) {
    log!("SetGCInProgress");
}

extern "C" fn runtime_structures_valid(this: *mut IGCHeapFFI) -> bool {
    log!("RuntimeStructuresValid");
    false
}

extern "C" fn set_suspension_pending(this: *mut IGCHeapFFI, fSuspensionPending: bool) {
    log!("SetSuspensionPending");
}

extern "C" fn set_yield_processor_scaling_factor(
    this: *mut IGCHeapFFI,
    yieldProcessorScalingFactor: c_float,
) {
    log!("SetYieldProcessorScalingFactor");
}

extern "C" fn shutdown(this: *mut IGCHeapFFI) {
    log!("Shutdown");
}

// Add/RemoveMemoryPressure support
extern "C" fn get_last_gc_start_time(this: *mut IGCHeapFFI, generation: c_int) -> usize {
    log!("GetLastGCStartTime");
    0
}

extern "C" fn get_last_gc_duration(this: *mut IGCHeapFFI, generation: c_int) -> usize {
    log!("GetLastGCDuration");
    0
}

extern "C" fn get_now(this: *mut IGCHeapFFI) -> usize {
    log!("GetNow");
    0
}

// Allocation
extern "C" fn alloc(
    this: *mut IGCHeapFFI,
    acontext: *mut gc_alloc_context,
    size: usize,
    flags: u32,
) -> *mut Object {
    log!("Alloc");
    null_mut()
}

extern "C" fn publish_object(this: *mut IGCHeapFFI, obj: *mut u8) {
    log!("PublishObject: {:#x}", obj as usize);
}

extern "C" fn set_wait_for_gc_event(this: *mut IGCHeapFFI) {
    log!("SetWaitForGCEvent");
}

extern "C" fn reset_wait_for_gc_event(this: *mut IGCHeapFFI) {
    log!("ResetWaitForGCEvent");
}

// Heap Verification
extern "C" fn is_large_object(this: *mut IGCHeapFFI, pObj: *mut Object) -> bool {
    log!("IsLargeObject");
    false
}

extern "C" fn validate_object_member(this: *mut IGCHeapFFI, obj: *mut Object) {
    log!("ValidateObjectMember");
}

extern "C" fn next_obj(this: *mut IGCHeapFFI, object: *mut Object) -> *mut Object {
    log!("NextObj");
    null_mut()
}

extern "C" fn get_containing_object(
    this: *mut IGCHeapFFI,
    pInteriorPtr: *mut c_void,
    fCollectedGenOnly: bool,
) -> *mut Object {
    log!("GetContainingObject");
    null_mut()
}

// Profiling
extern "C" fn diag_walk_object(
    this: *mut IGCHeapFFI,
    obj: *mut Object,
    fn_: walk_fn,
    context: *mut c_void,
) {
    log!("DiagWalkObject");
}

extern "C" fn diag_walk_object2(
    this: *mut IGCHeapFFI,
    obj: *mut Object,
    fn_: walk_fn2,
    context: *mut c_void,
) {
    log!("DiagWalkObject2");
}

extern "C" fn diag_walk_heap(
    this: *mut IGCHeapFFI,
    fn_: walk_fn,
    context: *mut c_void,
    gen_number: c_int,
    walk_large_object_heap_p: bool,
) {
    log!("DiagWalkHeap");
}

extern "C" fn diag_walk_survivors_with_type(
    this: *mut IGCHeapFFI,
    gc_context: *mut c_void,
    fn_: record_surv_fn,
    diag_context: *mut c_void,
    type_: walk_surv_type,
    gen_number: c_int,
) {
    log!("DiagWalkSurvivorsWithType");
}

extern "C" fn diag_walk_finalize_queue(
    this: *mut IGCHeapFFI,
    gc_context: *mut c_void,
    fn_: fq_walk_fn,
) {
    log!("DiagWalkFinalizeQueue");
}

extern "C" fn diag_scan_finalize_queue(
    this: *mut IGCHeapFFI,
    fn_: fq_scan_fn,
    context: *mut ScanContext,
) {
    log!("DiagScanFinalizeQueue");
}

extern "C" fn diag_scan_handles(
    this: *mut IGCHeapFFI,
    fn_: handle_scan_fn,
    gen_number: c_int,
    context: *mut ScanContext,
) {
    log!("DiagScanHandles");
}

extern "C" fn diag_scan_dependent_handles(
    this: *mut IGCHeapFFI,
    fn_: handle_scan_fn,
    gen_number: c_int,
    context: *mut ScanContext,
) {
    log!("DiagScanDependentHandles");
}

extern "C" fn diag_descr_generations(
    this: *mut IGCHeapFFI,
    fn_: gen_walk_fn,
    context: *mut c_void,
) {
    log!("DiagDescrGenerations");
}

extern "C" fn diag_trace_gc_segments(this: *mut IGCHeapFFI) {
    log!("DiagTraceGCSegments");
}

extern "C" fn diag_get_gc_settings(this: *mut IGCHeapFFI, settings: *mut EtwGCSettingsInfo) {
    log!("DiagGetGCSettings");
}

// GC Stress
extern "C" fn stress_heap(this: *mut IGCHeapFFI, acontext: *mut gc_alloc_context) -> bool {
    log!("StressHeap");
    false
}

// Frozen Objects
extern "C" fn register_frozen_segment(
    this: *mut IGCHeapFFI,
    pseginfo: *mut segment_info,
) -> segment_handle {
    log!("RegisterFrozenSegment");
    null_mut()
}

extern "C" fn unregister_frozen_segment(this: *mut IGCHeapFFI, seg: segment_handle) {
    log!("UnregisterFrozenSegment");
}

extern "C" fn is_in_frozen_segment(this: *mut IGCHeapFFI, object: *mut Object) -> bool {
    log!("IsInFrozenSegment");
    false
}

// Event Control
extern "C" fn control_events(this: *mut IGCHeapFFI, keyword: GCEventKeyword, level: GCEventLevel) {
    log!("control_events")
}
extern "C" fn control_private_events(
    this: *mut IGCHeapFFI,
    keyword: GCEventKeyword,
    level: GCEventLevel,
) {
    log!("control_private_events")
}

extern "C" fn get_generation_with_range(
    this: *mut IGCHeapFFI,
    object: *mut Object,
    ppStart: *mut *mut u8,
    ppAllocated: *mut *mut u8,
    ppReserved: *mut *mut u8,
) -> c_uint {
    log!("GetGenerationWithRange");
    0
}

// New additions
extern "C" fn get_total_pause_duration(this: *mut IGCHeapFFI) -> i64 {
    log!("GetTotalPauseDuration");
    0
}
extern "C" fn enum_configuration_values(
    this: *mut IGCHeapFFI,
    context: *mut c_void,
    configurationValueFunc: ConfigurationValueFunc,
) {
    log!("EnumConfigurationValues");
}
extern "C" fn update_frozen_segment(
    this: *mut IGCHeapFFI,
    seg: segment_handle,
    allocated: *mut u8,
    committed: *mut u8,
) {
    log!("UpdateFrozenSegment");
}
extern "C" fn refresh_memory_limit(this: *mut IGCHeapFFI) -> c_int {
    log!("RefreshMemoryLimit");
    0
}

extern "C" fn enables_no_gc_region_callback_status(
    this: *mut IGCHeapFFI,
    callback: *mut NoGCRegionCallbackFinalizerWorkItem,
    callback_threshold: u64,
) -> enable_no_gc_region_callback_status {
    log!("EnablesNoGCRegionCallbackStatus");
    enable_no_gc_region_callback_status::succeed
}

extern "C" fn get_extra_work_for_finalization(this: *mut IGCHeapFFI) -> *mut FinalizerWorkItem {
    log!("GetExtraWorkForFinalization");
    std::ptr::null_mut()
}
extern "C" fn get_generation_budget(this: *mut IGCHeapFFI, generation: c_int) -> u64 {
    log!("GetGenerationBudget");
    0
}
extern "C" fn get_loh_threshold(this: *mut IGCHeapFFI) -> usize {
    log!("GetLOHThreshold");
    0
}

extern "C" fn diag_walk_heap_with_ac_handling(
    this: *mut IGCHeapFFI,
    fn_: walk_fn,
    context: *mut c_void,
    gen_number: c_int,
    walk_large_object_heap_p: bool,
) {
    log!("DiagWalkHeapWithACHandling");
}

// Create a static VTable. All unimplemented methods will panic.
// A production GC would need to implement more of these.
static GCHEAP_VTABLE: IGCHeapVTable = IGCHeapVTable {
    Initialize: heap_initialize,
    Alloc: heap_alloc,
    GarbageCollect: heap_garbage_collect,

    // Most other methods can be no-ops or return default values for this simple GC.
    IsValidSegmentSize: is_valid_segment_size,
    IsValidGen0MaxSize: is_valid_gen0_max_size,
    GetValidSegmentSize: get_valid_segment_size, // 1MB
    SetReservedVMLimit: set_reserved_vm_limit,
    WaitUntilConcurrentGCComplete: wait_until_concurrent_gc_complete,
    IsConcurrentGCInProgress: is_concurrent_gc_in_progress,
    TemporaryEnableConcurrentGC: temporary_enable_concurrent_gc,
    TemporaryDisableConcurrentGC: temporary_disable_concurrent_gc,
    IsConcurrentGCEnabled: is_concurrent_gc_enabled,
    GetMaxGeneration: get_max_generation,
    WhichGeneration: which_generation,
    CollectionCount: collection_count,
    IsPromoted: is_promoted,        // Nothing is ever promoted
    IsHeapPointer: is_heap_pointer, // A lie, but good enough
    GetGcCount: get_gc_count,
    WaitUntilConcurrentGCCompleteAsync: wait_until_concurrent_gc_complete_async,
    GetNumberOfFinalizable: get_number_of_finalizable,
    GetNextFinalizable: get_next_finalizable,
    GetMemoryInfo: get_memory_info,
    GetMemoryLoad: get_memory_load,
    GetGcLatencyMode: get_gc_latency_mode,
    SetGcLatencyMode: set_gc_latency_mode,
    GetLOHCompactionMode: get_loh_compaction_mode,
    SetLOHCompactionMode: set_loh_compaction_mode,
    RegisterForFullGCNotification: register_for_full_gc_notification,
    CancelFullGCNotification: cancel_full_gc_notification,
    WaitForFullGCApproach: wait_for_full_gc_approach,
    WaitForFullGCComplete: wait_for_full_gc_complete,
    StartNoGCRegion: start_no_gc_region,
    EndNoGCRegion: end_no_gc_region,
    GetTotalBytesInUse: get_total_bytes_in_use,
    GetTotalAllocatedBytes: get_total_allocated_bytes,
    SetFinalizationRun: set_finalization_run,
    RegisterForFinalization: register_for_finalization,
    GetLastGCPercentTimeInGC: get_last_gc_percent_time_in_gc,
    GetLastGCGenerationSize: get_last_gc_generation_size,
    GetCondemnedGeneration: get_condemned_generation,
    IsGCInProgressHelper: is_gc_in_progress_helper,
    IsThreadUsingAllocationContextHeap: is_thread_using_allocation_context_heap,
    IsEphemeral: is_ephemeral,
    WaitUntilGCComplete: wait_until_gc_complete,
    FixAllocContext: fix_alloc_context,
    GetCurrentObjSize: get_current_obj_size,
    SetGCInProgress: set_gc_in_progress,
    RuntimeStructuresValid: runtime_structures_valid,
    SetSuspensionPending: set_suspension_pending,
    SetYieldProcessorScalingFactor: set_yield_processor_scaling_factor,
    Shutdown: shutdown,
    GetLastGCStartTime: get_last_gc_start_time,
    GetLastGCDuration: get_last_gc_duration,
    GetNow: get_now,
    PublishObject: publish_object,
    SetWaitForGCEvent: set_wait_for_gc_event,
    ResetWaitForGCEvent: reset_wait_for_gc_event,
    IsLargeObject: is_large_object,
    ValidateObjectMember: validate_object_member,
    NextObj: next_obj,
    GetContainingObject: get_containing_object,
    DiagWalkObject: diag_walk_object,
    DiagWalkObject2: diag_walk_object2,
    DiagWalkHeap: diag_walk_heap,
    DiagWalkSurvivorsWithType: diag_walk_survivors_with_type,
    DiagWalkFinalizeQueue: diag_walk_finalize_queue,
    DiagScanFinalizeQueue: diag_scan_finalize_queue,
    DiagScanHandles: diag_scan_handles,
    DiagScanDependentHandles: diag_scan_dependent_handles,
    DiagDescrGenerations: diag_descr_generations,
    DiagTraceGCSegments: diag_trace_gc_segments,
    DiagGetGCSettings: diag_get_gc_settings,
    StressHeap: stress_heap,
    RegisterFrozenSegment: register_frozen_segment,
    UnregisterFrozenSegment: unregister_frozen_segment,
    IsInFrozenSegment: is_in_frozen_segment,
    ControlEvents: control_events,
    ControlPrivateEvents: control_private_events,
    GetGenerationWithRange: get_generation_with_range,
    GetTotalPauseDuration: get_total_pause_duration,
    EnumerateConfigurationValues: enum_configuration_values,
    UpdateFrozenSegment: update_frozen_segment,
    RefreshMemoryLimit: refresh_memory_limit,
    EnableNoGCRegionCallback: enables_no_gc_region_callback_status,
    GetExtraWorkForFinalization: get_extra_work_for_finalization,
    GetGenerationBudget: get_generation_budget,
    GetLOHThreshold: get_loh_threshold,
    DiagWalkHeapWithACHandling: diag_walk_heap_with_ac_handling,
};
