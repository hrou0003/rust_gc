// lib.rs

#![allow(non_snake_case, unused_variables, dead_code)]

// Import our FFI definitions
mod interfaces;
use interfaces::*;

use std::alloc::{alloc_zeroed, Layout};
use std::ffi::{c_float, c_uint, c_void};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicIsize, Ordering};

// A helper for printing debug messages, like the article's `Write` method
macro_rules! log {
    ($($arg:tt)*) => {
        println!("[MyRustGC] {}", format!($($arg)*));
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

const MAX_HANDLES: usize = 10_000;

/// Our concrete representation of a GC handle in memory.
/// We assume an OBJECTHANDLE from the runtime is a pointer to this struct.
#[repr(C)]
#[derive(Debug)]
struct ObjectHandle {
    pub object: *mut Object,
    pub extra_info: *mut c_void,
    pub type_: HandleType,
}

#[repr(C)]
struct MyGCHandleStore {
    // The FFI interface must be the first field for pointer casting to work.
    ffi: IGCHandleStoreFFI,
    store: *mut ObjectHandle,
    handle_count: AtomicIsize,
}

impl MyGCHandleStore {
    fn new() -> Self {
        log!("Allocating handle store ({} handles)", MAX_HANDLES);
        let layout = Layout::array::<ObjectHandle>(MAX_HANDLES).unwrap();
        let store_ptr = unsafe { alloc_zeroed(layout) as *mut ObjectHandle };
        if store_ptr.is_null() {
            panic!("Failed to allocate memory for handle store");
        }

        Self {
            ffi: IGCHandleStoreFFI {
                vtable: &GCHANDLESTORE_VTABLE,
            },
            store: store_ptr,
            handle_count: AtomicIsize::new(0),
        }
    }

    // The actual implementation of CreateHandleWithExtraInfo
    fn create_handle_with_extra_info_impl(
        &mut self,
        object: *mut Object,
        type_: HandleType,
        extra_info: *mut c_void,
    ) -> OBJECTHANDLE {
        let index = self.handle_count.fetch_add(1, Ordering::SeqCst);
        if index >= MAX_HANDLES as isize {
            // The C# code uses FailFast. We'll panic.
            panic!("Too many handles! Limit is {}.", MAX_HANDLES);
        }

        unsafe {
            let handle_ptr = self.store.offset(index);
            (*handle_ptr).object = object;
            (*handle_ptr).type_ = type_;
            (*handle_ptr).extra_info = extra_info;

            // Return a pointer to our handle struct as the opaque OBJECTHANDLE
            handle_ptr as OBJECTHANDLE
        }
    }

    // The actual implementation of ContainsHandle
    fn contains_handle_impl(&self, handle: OBJECTHANDLE) -> bool {
        let handle_ptr = handle as *const ObjectHandle;
        let start = self.store as *const ObjectHandle;
        let end = unsafe { start.add(self.handle_count.load(Ordering::SeqCst) as usize) };
        handle_ptr >= start && handle_ptr < end
    }

    fn dump_handles_impl(&self) {
        log!("--- Dumping Handles ---");
        let count = self.handle_count.load(Ordering::SeqCst) as usize;
        for i in 0..count {
            let handle = unsafe { &*self.store.add(i) };
            log!("Handle {}: {:?}", i, handle);
        }
        log!("--- End of Handle Dump ---");
    }

    pub fn create_handle_of_type(
        &mut self,
        object: *mut Object,
        type_: HandleType,
    ) -> Result<OBJECTHANDLE, &'static str> {
        // Return OBJECTHANDLE directly

        if object.is_null() {
            log!("MyGCHandleStore::create_object_handle: object pointer is null");
            return Err("Object pointer cannot be null");
        }
        let handle = self.get_next_available_handle();
        Ok(handle as OBJECTHANDLE)
    }

    pub fn get_next_available_handle(&mut self) -> OBJECTHANDLE {
        let handle = self.handle_count.fetch_add(1, Ordering::SeqCst);
        handle as OBJECTHANDLE
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
        Ok(self
            .store
            .create_handle_with_extra_info_impl(object, type_, std::ptr::null_mut()))
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
        log!("Initialize GCHeap");

        // This trick disables the write barrier for workstation GC
        // by setting a range that no pointer can fall into.
        let params = WriteBarrierParameters {
            operation: WriteBarrierOp::Initialize,
            is_runtime_suspended: true,
            requires_upper_bounds_check: false, // Not relevant for Initialize
            card_table: std::ptr::null_mut(),
            card_bundle_table: std::ptr::null_mut(),
            lowest_address: std::ptr::null_mut(),
            highest_address: std::ptr::null_mut(),
            ephemeral_low: -1_isize as *mut u8, // u64::MAX
            ephemeral_high: std::ptr::null_mut(),
            write_watch_table: std::ptr::null_mut(),
            region_to_generation_table: std::ptr::null_mut(),
            region_shr: 0,
            region_use_bitwise_write_barrier: false,
        };

        unsafe {
            (*self.clr_to_gc).stomp_write_barrier(&params);
        }

        0 // S_OK
    }

    // The actual implementation of Alloc
    fn alloc_impl(
        &mut self,
        acontext: &mut gc_alloc_context,
        size: usize,
        flags: u32,
    ) -> *mut Object {
        let result = acontext.alloc_ptr;
        let advance = unsafe { result.add(size) };

        if advance <= acontext.alloc_limit {
            // Fast path: current allocation context has enough space.
            acontext.alloc_ptr = advance;
            return result as *mut Object;
        }

        // Slow path: need to get a new chunk of memory for the context.
        log!("Allocating new chunk for context. Requested size: {}", size);

        // Allocate at least 32KB, or more if the object is bigger.
        // Add space for the object header (1 pointer size).
        let growth_size = (size.max(32 * 1024)) + std::mem::size_of::<usize>();
        let layout = Layout::from_size_align(growth_size, 8).unwrap();
        let new_pages = unsafe { alloc_zeroed(layout) };

        if new_pages.is_null() {
            return std::ptr::null_mut(); // Out of memory
        }

        // The object pointer is offset by one pointer to leave space for the header.
        let allocation_start = unsafe { new_pages.add(std::mem::size_of::<usize>()) };
        acontext.alloc_ptr = unsafe { allocation_start.add(size) };
        acontext.alloc_limit = unsafe { new_pages.add(growth_size) };

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

extern "C" fn store_uproot(this: *mut IGCHandleStoreFFI) { /* no-op */
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
    store.create_handle_with_extra_info_impl(object, type_, std::ptr::null_mut())
}
extern "C" fn store_create_handle_affinitized(
    this: *mut IGCHandleStoreFFI,
    object: *mut Object,
    type_: HandleType,
    heap: c_int,
) -> OBJECTHANDLE {
    let store = unsafe { &mut *(this as *mut MyGCHandleStore) };
    store.create_handle_with_extra_info_impl(object, type_, std::ptr::null_mut())
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
    store.create_handle_with_extra_info_impl(primary, HandleType::DEPENDENT, secondary as *mut _)
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
    manager
        .store
        .create_handle_with_extra_info_impl(object, type_, std::ptr::null_mut())
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
    unsafe { (*(handle as *mut ObjectHandle)).type_ }
}

unimplemented_shim!(mgr_destroy_store, this: *mut IGCHandleManagerFFI, store: *mut IGCHandleStoreFFI);
// ... many other shims omitted for brevity but required for a complete VTable

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
    todo!()
}

extern "C" fn is_valid_gen0_max_size(this: *mut IGCHeapFFI, size: usize) -> bool {
    todo!()
}

extern "C" fn get_valid_segment_size(this: *mut IGCHeapFFI, large_seg: bool) -> usize {
    todo!()
}

extern "C" fn set_reserved_vm_limit(this: *mut IGCHeapFFI, vmlimit: usize) {
    todo!()
}

// Concurrent GC
extern "C" fn wait_until_concurrent_gc_complete(this: *mut IGCHeapFFI) {
    todo!()
}

extern "C" fn is_concurrent_gc_in_progress(this: *mut IGCHeapFFI) -> bool {
    todo!()
}

extern "C" fn temporary_enable_concurrent_gc(this: *mut IGCHeapFFI) {
    todo!()
}

extern "C" fn temporary_disable_concurrent_gc(this: *mut IGCHeapFFI) {
    todo!()
}

extern "C" fn is_concurrent_gc_enabled(this: *mut IGCHeapFFI) -> bool {
    todo!()
}

extern "C" fn wait_until_concurrent_gc_complete_async(
    this: *mut IGCHeapFFI,
    millisecondsTimeout: c_int,
) -> HRESULT {
    todo!()
}

// Finalization
extern "C" fn get_number_of_finalizable(this: *mut IGCHeapFFI) -> usize {
    todo!()
}

extern "C" fn get_next_finalizable(this: *mut IGCHeapFFI) -> *mut Object {
    todo!()
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
    todo!()
}

extern "C" fn get_memory_load(this: *mut IGCHeapFFI) -> u32 {
    todo!()
}

extern "C" fn get_gc_latency_mode(this: *mut IGCHeapFFI) -> c_int {
    todo!()
}

extern "C" fn set_gc_latency_mode(this: *mut IGCHeapFFI, newLatencyMode: c_int) -> c_int {
    todo!()
}

extern "C" fn get_loh_compaction_mode(this: *mut IGCHeapFFI) -> c_int {
    todo!()
}

extern "C" fn set_loh_compaction_mode(this: *mut IGCHeapFFI, newLOHCompactionMode: c_int) {
    todo!()
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
    todo!()
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
    todo!()
}

extern "C" fn is_gc_in_progress_helper(this: *mut IGCHeapFFI, bConsiderGCStart: bool) -> bool {
    todo!()
}

extern "C" fn get_gc_count(this: *mut IGCHeapFFI) -> c_uint {
    todo!()
}

extern "C" fn is_thread_using_allocation_context_heap(
    this: *mut IGCHeapFFI,
    acontext: *mut gc_alloc_context,
    thread_number: c_int,
) -> bool {
    todo!()
}

extern "C" fn is_ephemeral(this: *mut IGCHeapFFI, object: *mut Object) -> bool {
    todo!()
}

extern "C" fn wait_until_gc_complete(this: *mut IGCHeapFFI, bConsiderGCStart: bool) -> u32 {
    todo!()
}

extern "C" fn fix_alloc_context(
    this: *mut IGCHeapFFI,
    acontext: *mut gc_alloc_context,
    arg: *mut c_void,
    heap: *mut c_void,
) {
    todo!()
}

extern "C" fn get_current_obj_size(this: *mut IGCHeapFFI) -> usize {
    todo!()
}

extern "C" fn set_gc_in_progress(this: *mut IGCHeapFFI, fInProgress: bool) {
    todo!()
}

extern "C" fn runtime_structures_valid(this: *mut IGCHeapFFI) -> bool {
    todo!()
}

extern "C" fn set_suspension_pending(this: *mut IGCHeapFFI, fSuspensionPending: bool) {
    todo!()
}

extern "C" fn set_yield_processor_scaling_factor(
    this: *mut IGCHeapFFI,
    yieldProcessorScalingFactor: c_float,
) {
    todo!()
}

extern "C" fn shutdown(this: *mut IGCHeapFFI) {
    todo!()
}

// Add/RemoveMemoryPressure support
extern "C" fn get_last_gc_start_time(this: *mut IGCHeapFFI, generation: c_int) -> usize {
    todo!()
}

extern "C" fn get_last_gc_duration(this: *mut IGCHeapFFI, generation: c_int) -> usize {
    todo!()
}

extern "C" fn get_now(this: *mut IGCHeapFFI) -> usize {
    todo!()
}

// Allocation
extern "C" fn alloc(
    this: *mut IGCHeapFFI,
    acontext: *mut gc_alloc_context,
    size: usize,
    flags: u32,
) -> *mut Object {
    todo!()
}

extern "C" fn publish_object(this: *mut IGCHeapFFI, obj: *mut u8) {
    todo!()
}

extern "C" fn set_wait_for_gc_event(this: *mut IGCHeapFFI) {
    todo!()
}

extern "C" fn reset_wait_for_gc_event(this: *mut IGCHeapFFI) {
    todo!()
}

// Heap Verification
extern "C" fn is_large_object(this: *mut IGCHeapFFI, pObj: *mut Object) -> bool {
    todo!()
}

extern "C" fn validate_object_member(this: *mut IGCHeapFFI, obj: *mut Object) {
    todo!()
}

extern "C" fn next_obj(this: *mut IGCHeapFFI, object: *mut Object) -> *mut Object {
    todo!()
}

extern "C" fn get_containing_object(
    this: *mut IGCHeapFFI,
    pInteriorPtr: *mut c_void,
    fCollectedGenOnly: bool,
) -> *mut Object {
    todo!()
}

// Profiling
extern "C" fn diag_walk_object(
    this: *mut IGCHeapFFI,
    obj: *mut Object,
    fn_: walk_fn,
    context: *mut c_void,
) {
    todo!()
}

extern "C" fn diag_walk_object2(
    this: *mut IGCHeapFFI,
    obj: *mut Object,
    fn_: walk_fn2,
    context: *mut c_void,
) {
    todo!()
}

extern "C" fn diag_walk_heap(
    this: *mut IGCHeapFFI,
    fn_: walk_fn,
    context: *mut c_void,
    gen_number: c_int,
    walk_large_object_heap_p: bool,
) {
    todo!()
}

extern "C" fn diag_walk_survivors_with_type(
    this: *mut IGCHeapFFI,
    gc_context: *mut c_void,
    fn_: record_surv_fn,
    diag_context: *mut c_void,
    type_: walk_surv_type,
    gen_number: c_int,
) {
    todo!()
}

extern "C" fn diag_walk_finalize_queue(
    this: *mut IGCHeapFFI,
    gc_context: *mut c_void,
    fn_: fq_walk_fn,
) {
    todo!()
}

extern "C" fn diag_scan_finalize_queue(
    this: *mut IGCHeapFFI,
    fn_: fq_scan_fn,
    context: *mut ScanContext,
) {
    todo!()
}

extern "C" fn diag_scan_handles(
    this: *mut IGCHeapFFI,
    fn_: handle_scan_fn,
    gen_number: c_int,
    context: *mut ScanContext,
) {
    todo!()
}

extern "C" fn diag_scan_dependent_handles(
    this: *mut IGCHeapFFI,
    fn_: handle_scan_fn,
    gen_number: c_int,
    context: *mut ScanContext,
) {
    todo!()
}

extern "C" fn diag_descr_generations(
    this: *mut IGCHeapFFI,
    fn_: gen_walk_fn,
    context: *mut c_void,
) {
    todo!()
}

extern "C" fn diag_trace_gc_segments(this: *mut IGCHeapFFI) {
    todo!()
}

extern "C" fn diag_get_gc_settings(this: *mut IGCHeapFFI, settings: *mut EtwGCSettingsInfo) {
    todo!()
}

// GC Stress
extern "C" fn stress_heap(this: *mut IGCHeapFFI, acontext: *mut gc_alloc_context) -> bool {
    todo!()
}

// Frozen Objects
extern "C" fn register_frozen_segment(
    this: *mut IGCHeapFFI,
    pseginfo: *mut segment_info,
) -> segment_handle {
    todo!()
}

extern "C" fn unregister_frozen_segment(this: *mut IGCHeapFFI, seg: segment_handle) {
    todo!()
}

extern "C" fn is_in_frozen_segment(this: *mut IGCHeapFFI, object: *mut Object) -> bool {
    todo!()
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
    todo!()
}

// New additions
extern "C" fn get_total_pause_duration(this: *mut IGCHeapFFI) -> i64 {
    todo!()
}
extern "C" fn enum_configuration_values(
    this: *mut IGCHeapFFI,
    context: *mut c_void,
    configurationValueFunc: ConfigurationValueFunc,
) {
    todo!()
}
extern "C" fn update_frozen_segment(
    this: *mut IGCHeapFFI,
    seg: segment_handle,
    allocated: *mut u8,
    committed: *mut u8,
) {
    todo!()
}
extern "C" fn refresh_memory_limit(this: *mut IGCHeapFFI) -> c_int {
    todo!()
}
extern "C" fn enables_no_gc_region_callback_status(
    this: *mut IGCHeapFFI,
    callback: *mut NoGCRegionCallbackFinalizerWorkItem,
    callback_threshold: u64,
) -> enable_no_gc_region_callback_status {
    todo!()
}
extern "C" fn get_extra_work_for_finalization(this: *mut IGCHeapFFI) -> *mut FinalizerWorkItem {
    todo!()
}
extern "C" fn get_generation_budget(this: *mut IGCHeapFFI, generation: c_int) -> u64 {
    todo!()
}
extern "C" fn get_loh_threshold(this: *mut IGCHeapFFI) -> usize {
    todo!()
}
extern "C" fn diag_walk_heap_with_ac_handling(
    this: *mut IGCHeapFFI,
    fn_: walk_fn,
    context: *mut c_void,
    gen_number: c_int,
    walk_large_object_heap_p: bool,
) {
    todo!()
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
