use crate::gc_handle_manager::MyGCHandleManager;
use crate::interfaces::{
    enable_no_gc_region_callback_status, gc_alloc_context, walk_fn, walk_fn2, walk_surv_type,
    ConfigurationValueFunc, EtwGCSettingsInfo, FinalizerWorkItem, GCEventKeyword, GCEventLevel,
    HRESULT, IGCHeapFFI, IGCHeapVTable, IGCToCLR, NoGCRegionCallbackFinalizerWorkItem,
    Object, WriteBarrierOp, WriteBarrierParameters, fq_scan_fn, fq_walk_fn, gen_walk_fn,
    handle_scan_fn, record_surv_fn, segment_handle, segment_info,
};
use std::alloc::{alloc, alloc_zeroed, Layout};
use std::ffi::{c_float, c_uint, c_void};
use std::os::raw::c_int;
use std::ptr;
use std::ptr::null_mut;

#[repr(C)]
pub struct MyGCHeap {
    pub ffi: IGCHeapFFI,
    pub clr_to_gc: *mut IGCToCLR,
    pub handle_manager: Box<MyGCHandleManager>,
    pub heap_start: *mut u8,
    pub next_alloc_ptr: *mut u8,
    pub alloc_limit: *mut u8,
    frozen_segments: Vec<*mut u8>,
    // The heap state is managed entirely through the gc_alloc_context,
    // so no top-level heap pointers are needed here, matching the C++ ZeroGCHeap design.
}

const ARENA_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
const ALIGN: usize = 8; // .NET objects are 8-byte aligned on 64-bit targets
const OBJ_HEADER_BYTES: usize = std::mem::size_of::<usize>();
const OBJ_ALIGN: usize = 8;
#[inline]
fn align_up(ptr: *mut u8, align: usize) -> *mut u8 {
    debug_assert!(align.is_power_of_two());
    let addr = ptr as usize;
    let aligned = (addr + (align - 1)) & !(align - 1);
    aligned as *mut u8
}

impl MyGCHeap {
    pub(crate) fn new(clr_to_gc: *mut IGCToCLR) -> Self {
        Self {
            ffi: IGCHeapFFI {
                vtable: &GCHEAP_VTABLE,
            },
            clr_to_gc,
            handle_manager: Box::new(MyGCHandleManager::new()),
            alloc_limit: 0 as *mut u8,
            next_alloc_ptr: 0 as *mut u8,
            heap_start: 0 as *mut u8,
            frozen_segments: Vec::new()
        }
    }

    // The actual implementation of Initialize, matching C++ ZeroGCHeap.
    #[no_mangle]
    pub(crate) fn initialize_impl(&mut self) -> HRESULT {
        log!("Initialize called");

        // 1) Reserve a simple bump-pointer arena for the managed heap.
        // Pick a size large enough for startup.
        const HEAP_BYTES: usize = 128 * 1024 * 1024; // 64 MiB

        // Allocate raw memory and leak it (simple bring-up)
        let layout = std::alloc::Layout::from_size_align(HEAP_BYTES, 16).unwrap();
        let arena = unsafe { std::alloc::alloc(layout) };
        if arena.is_null() {
            panic!("[MyGCHeap] Failed to allocate heap arena");
        }

        // Initialize bump pointers
        self.heap_start = arena;
        self.next_alloc_ptr = arena;
        self.alloc_limit = unsafe { arena.add(HEAP_BYTES) };
        debug_assert!(self.heap_start <= self.next_alloc_ptr, "heap_start must be below alloc_limit");

        // 2) Keep your current write-barrier initialization
        // (dummy card table and extreme bounds) as you already had.
        let dummy_card_table_layout = Layout::new::<u32>();
        let dummy_card_table = unsafe { alloc(dummy_card_table_layout) as *mut u8 };
        if dummy_card_table.is_null() {
            panic!("[MyGCHeap] Failed to allocate dummy card table!");
        }

        let params = WriteBarrierParameters {
            operation: WriteBarrierOp::Initialize,
            is_runtime_suspended: true,
            requires_upper_bounds_check: false,
            card_table: dummy_card_table,
            card_bundle_table: ptr::null_mut(),
            lowest_address: !0_usize as *mut u8,
            highest_address: 1_usize as *mut u8,
            ephemeral_low: !0_usize as *mut u8,
            ephemeral_high: 1_usize as *mut u8,
            write_watch_table: ptr::null_mut(),
            region_to_generation_table: ptr::null_mut(),
            region_shr: 0,
            region_use_bitwise_write_barrier: false,
        };

        unsafe {
            (*self.clr_to_gc).stomp_write_barrier(&params);
        }

        log!("GCHeap initialization completed successfully.");
        0 // S_OK
    }


    // Rust
    // The core allocation logic: refill the thread's alloc context from our single arena.
    // Objects always come from [heap_start .. alloc_limit), so IsHeapPointer will succeed.
    // alloc_ptr is always the header address; we bump by header + aligned payload
    pub fn alloc_impl(
        &mut self,
        acontext: &mut gc_alloc_context,
        size: usize,
        _flags: u32,
    ) -> *mut Object {
        let payload = (size + (OBJ_ALIGN - 1)) & !(OBJ_ALIGN - 1);
        let total = OBJ_HEADER_BYTES + payload;

        // Fast path in the current slice
        let header_ptr = align_up(acontext.alloc_ptr, OBJ_HEADER_BYTES);
        let fast_end = unsafe { header_ptr.add(total) };
        if fast_end <= acontext.alloc_limit {
            let obj = unsafe { header_ptr.add(OBJ_HEADER_BYTES) as *mut Object };
            // Zero header + payload
            unsafe { ptr::write_bytes(header_ptr, 0, total) };
            acontext.alloc_ptr = fast_end;

            debug_assert_eq!((obj as usize) & (OBJ_ALIGN - 1), 0);
            return obj;
        }
        
        // Asset allocation is within range
        debug_assert!(self.next_alloc_ptr < self.alloc_limit);

        // Refill from global arena
        const REFILL_CHUNK: usize = 256 * 1024;
        let refill_bytes = total.max(REFILL_CHUNK);

        self.next_alloc_ptr = align_up(self.next_alloc_ptr, OBJ_HEADER_BYTES);
        let new_end = unsafe { self.next_alloc_ptr.add(refill_bytes) };
        if new_end > self.alloc_limit {
            return ptr::null_mut();
        }

        acontext.alloc_ptr = self.next_alloc_ptr;
        acontext.alloc_limit = new_end;
        self.next_alloc_ptr = new_end;
        debug_assert!(self.heap_start <= self.next_alloc_ptr, "heap_start must be below alloc_limit");
        // Allocate in the new slice
        let header_ptr = align_up(acontext.alloc_ptr, OBJ_HEADER_BYTES);
        let obj = unsafe { header_ptr.add(OBJ_HEADER_BYTES) as *mut Object };
        unsafe {
            ptr::write_bytes(header_ptr, 0, total);
            acontext.alloc_ptr = header_ptr.add(total);
        }
        debug_assert_eq!((obj as usize) & (OBJ_ALIGN - 1), 0);
        log!("heap allocated {:?}", obj);
        obj
    }

    // Implementation of GarbageCollect, matching C++ ZeroGCHeap::GarbageCollect
    pub(crate) fn garbage_collect_impl(&mut self, _generation: i32) -> HRESULT {
        // Does nothing, just like the C++ version.
        0 // S_OK
    }
}

// --- IGCHeap VTable ---

extern "C" fn heap_initialize(this: *mut IGCHeapFFI) -> HRESULT {
    log!("Heap initialize");
    let heap = unsafe { &mut *(this as *mut MyGCHeap) };
    heap.initialize_impl()
}

#[no_mangle]
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
    _low_mem: bool,
    _mode: c_int,
) -> HRESULT {
    let heap = unsafe { &mut *(this as *mut MyGCHeap) };
    heap.garbage_collect_impl(generation)
}
extern "C" fn get_max_generation(_this: *mut IGCHeapFFI) -> c_uint {
    log!("GetMaxGeneration");
    1 // Match C++ implementation
}

#[no_mangle]
extern "C" fn is_heap_pointer(
    this: *mut IGCHeapFFI,
    object: *mut c_void,
    _small_heap_only: bool,
) -> bool {
    if object.is_null() && _small_heap_only {
        return false;
    }
    // Cast the FFI object back to your heap type
    let heap = unsafe { &*(this as *mut MyGCHeap) };

    let ptr = object as *mut u8;
    // Return true only if the pointer is inside the managed heap arena
    let is_heap_pointer = unsafe { heap.heap_start <= ptr && ptr < heap.next_alloc_ptr };
    debug_assert!(heap.heap_start < heap.next_alloc_ptr, "heap_start must be below alloc_limit");
    log!("is_heap_pointer {:?}, start {:?}, end {:?}, {}", ptr, heap.heap_start, heap.next_alloc_ptr, is_heap_pointer);
    is_heap_pointer || _small_heap_only
}


// --- The rest of the VTable functions are stubs, matching the C++ implementation ---

extern "C" fn is_valid_segment_size(_this: *mut IGCHeapFFI, _size: usize) -> bool {
    false
}

extern "C" fn is_valid_gen0_max_size(_this: *mut IGCHeapFFI, _size: usize) -> bool {
    false
}

extern "C" fn get_valid_segment_size(_this: *mut IGCHeapFFI, _large_seg: bool) -> usize {
    0
}

extern "C" fn set_reserved_vm_limit(_this: *mut IGCHeapFFI, _vmlimit: usize) {}

extern "C" fn wait_until_concurrent_gc_complete(_this: *mut IGCHeapFFI) {}

extern "C" fn is_concurrent_gc_in_progress(_this: *mut IGCHeapFFI) -> bool {
    false
}

extern "C" fn temporary_enable_concurrent_gc(_this: *mut IGCHeapFFI) {}

extern "C" fn temporary_disable_concurrent_gc(_this: *mut IGCHeapFFI) {}

extern "C" fn is_concurrent_gc_enabled(_this: *mut IGCHeapFFI) -> bool {
    false
}

extern "C" fn wait_until_concurrent_gc_complete_async(
    _this: *mut IGCHeapFFI,
    _millisecondsTimeout: c_int,
) -> HRESULT {
    0 // S_OK
}

extern "C" fn get_number_of_finalizable(_this: *mut IGCHeapFFI) -> usize {
    0
}

extern "C" fn get_next_finalizable(_this: *mut IGCHeapFFI) -> *mut Object {
    ptr::null_mut()
}

extern "C" fn get_memory_info(
    _this: *mut IGCHeapFFI,
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
    _kind: c_int,
) {
    // Initialize all output parameters to zero/false as per C# and C++ stubs
    unsafe {
        if !highMemLoadThresholdBytes.is_null() { *highMemLoadThresholdBytes = 0; }
        if !totalAvailableMemoryBytes.is_null() { *totalAvailableMemoryBytes = 0; }
        if !lastRecordedMemLoadBytes.is_null() { *lastRecordedMemLoadBytes = 0; }
        if !lastRecordedHeapSizeBytes.is_null() { *lastRecordedHeapSizeBytes = 0; }
        if !lastRecordedFragmentationBytes.is_null() { *lastRecordedFragmentationBytes = 0; }
        if !totalCommittedBytes.is_null() { *totalCommittedBytes = 0; }
        if !promotedBytes.is_null() { *promotedBytes = 0; }
        if !pinnedObjectCount.is_null() { *pinnedObjectCount = 0; }
        if !finalizationPendingCount.is_null() { *finalizationPendingCount = 0; }
        if !index.is_null() { *index = 0; }
        if !generation.is_null() { *generation = 0; }
        if !pauseTimePct.is_null() { *pauseTimePct = 0; }
        if !isCompaction.is_null() { *isCompaction = false; }
        if !isConcurrent.is_null() { *isConcurrent = false; }
        if !genInfoRaw.is_null() { *genInfoRaw = 0; }
        if !pauseInfoRaw.is_null() { *pauseInfoRaw = 0; }
    }
}

extern "C" fn get_memory_load(_this: *mut IGCHeapFFI) -> u32 {
    0
}

extern "C" fn get_gc_latency_mode(_this: *mut IGCHeapFFI) -> c_int {
    0
}

extern "C" fn set_gc_latency_mode(_this: *mut IGCHeapFFI, _newLatencyMode: c_int) -> c_int {
    0
}

extern "C" fn get_loh_compaction_mode(_this: *mut IGCHeapFFI) -> c_int {
    0
}

extern "C" fn set_loh_compaction_mode(_this: *mut IGCHeapFFI, _newLOHCompactionMode: c_int) {}

extern "C" fn register_for_full_gc_notification(_this: *mut IGCHeapFFI, _gen: u32, _count: u32) -> bool {
    false
}

extern "C" fn cancel_full_gc_notification(_this: *mut IGCHeapFFI) -> bool {
    false
}


extern "C" fn wait_for_full_gc_approach(
    _this: *mut IGCHeapFFI,
    _millisecondsTimeout: c_int,
) -> c_int {
    0
}

extern "C" fn wait_for_full_gc_complete(
    _this: *mut IGCHeapFFI,
    _millisecondsTimeout: c_int,
) -> c_int {
    0
}

extern "C" fn which_generation(_this: *mut IGCHeapFFI, _obj: *mut Object) -> c_uint {
    0
}

extern "C" fn collection_count(
    _this: *mut IGCHeapFFI,
    _generation: c_int,
    _get_bgc_fgc_coutn: c_int,
) -> c_int {
    0
}

extern "C" fn start_no_gc_region(
    _this: *mut IGCHeapFFI,
    _totalSize: u64,
    _lohSizeKnown: bool,
    _lohSize: u64,
    _disallowFullBlockingGC: bool,
) -> c_int {
    0
}

extern "C" fn end_no_gc_region(_this: *mut IGCHeapFFI) -> c_int {
    0
}

extern "C" fn get_total_bytes_in_use(_this: *mut IGCHeapFFI) -> usize {
    0
}

extern "C" fn get_total_allocated_bytes(_this: *mut IGCHeapFFI) -> u64 {
    0
}

extern "C" fn set_finalization_run(_this: *mut IGCHeapFFI, _obj: *mut Object) {}

extern "C" fn register_for_finalization(
    _this: *mut IGCHeapFFI,
    _gen: c_int,
    _obj: *mut Object,
) -> bool {
    false
}

extern "C" fn get_last_gc_percent_time_in_gc(_this: *mut IGCHeapFFI) -> c_int {
    0
}

extern "C" fn get_last_gc_generation_size(_this: *mut IGCHeapFFI, _gen: c_int) -> usize {
    0
}

extern "C" fn is_promoted(_this: *mut IGCHeapFFI, _object: *mut Object) -> bool {
    false
}

extern "C" fn get_condemned_generation(_this: *mut IGCHeapFFI) -> c_uint {
    0
}

extern "C" fn is_gc_in_progress_helper(_this: *mut IGCHeapFFI, _bConsiderGCStart: bool) -> bool {
    false
}

extern "C" fn get_gc_count(_this: *mut IGCHeapFFI) -> c_uint {
    0
}

extern "C" fn is_thread_using_allocation_context_heap(
    _this: *mut IGCHeapFFI,
    _acontext: *mut gc_alloc_context,
    _thread_number: c_int,
) -> bool {
    false
}

extern "C" fn is_ephemeral(_this: *mut IGCHeapFFI, _object: *mut Object) -> bool {
    false
}

extern "C" fn wait_until_gc_complete(_this: *mut IGCHeapFFI, _bConsiderGCStart: bool) -> u32 {
    0
}

extern "C" fn fix_alloc_context(
    _this: *mut IGCHeapFFI,
    _acontext: *mut gc_alloc_context,
    _arg: *mut c_void,
    _heap: *mut c_void,
) {}

extern "C" fn get_current_obj_size(_this: *mut IGCHeapFFI) -> usize {
    0
}

extern "C" fn set_gc_in_progress(_this: *mut IGCHeapFFI, _fInProgress: bool) {}

extern "C" fn runtime_structures_valid(_this: *mut IGCHeapFFI) -> bool {
    true
}

extern "C" fn set_suspension_pending(_this: *mut IGCHeapFFI, _fSuspensionPending: bool) {}

extern "C" fn set_yield_processor_scaling_factor(
    _this: *mut IGCHeapFFI,
    _yieldProcessorScalingFactor: c_float,
) {}

extern "C" fn shutdown(_this: *mut IGCHeapFFI) {}

extern "C" fn get_last_gc_start_time(_this: *mut IGCHeapFFI, _generation: c_int) -> usize {
    0
}

extern "C" fn get_last_gc_duration(_this: *mut IGCHeapFFI, _generation: c_int) -> usize {
    0
}

extern "C" fn get_now(_this: *mut IGCHeapFFI) -> usize {
    0
}

extern "C" fn publish_object(_this: *mut IGCHeapFFI, _obj: *mut u8) {}

extern "C" fn set_wait_for_gc_event(_this: *mut IGCHeapFFI) {}

extern "C" fn reset_wait_for_gc_event(_this: *mut IGCHeapFFI) {}

extern "C" fn is_large_object(_this: *mut IGCHeapFFI, _pObj: *mut Object) -> bool {
    false
}

extern "C" fn validate_object_member(_this: *mut IGCHeapFFI, _obj: *mut Object) {}

extern "C" fn next_obj(_this: *mut IGCHeapFFI, _object: *mut Object) -> *mut Object {
    null_mut()
}

extern "C" fn get_containing_object(
    _this: *mut IGCHeapFFI,
    _pInteriorPtr: *mut c_void,
    _fCollectedGenOnly: bool,
) -> *mut Object {
    null_mut()
}

extern "C" fn diag_walk_object(
    _this: *mut IGCHeapFFI,
    _obj: *mut Object,
    _fn: walk_fn,
    _context: *mut c_void,
) {}

extern "C" fn diag_walk_object2(
    _this: *mut IGCHeapFFI,
    _obj: *mut Object,
    _fn: walk_fn2,
    _context: *mut c_void,
) {}

extern "C" fn diag_walk_heap(
    _this: *mut IGCHeapFFI,
    _fn: walk_fn,
    _context: *mut c_void,
    _gen_number: c_int,
    _walk_large_object_heap_p: bool,
) {}

extern "C" fn diag_walk_survivors_with_type(
    _this: *mut IGCHeapFFI,
    _gc_context: *mut c_void,
    _fn: record_surv_fn,
    _diag_context: *mut c_void,
    _type: walk_surv_type,
    _gen_number: c_int,
) {}

extern "C" fn diag_walk_finalize_queue(
    _this: *mut IGCHeapFFI,
    _gc_context: *mut c_void,
    _fn: fq_walk_fn,
) {}

extern "C" fn diag_scan_finalize_queue(
    _this: *mut IGCHeapFFI,
    _fn: fq_scan_fn,
    _context: *mut crate::interfaces::ScanContext,
) {}

extern "C" fn diag_scan_handles(
    _this: *mut IGCHeapFFI,
    _fn: handle_scan_fn,
    _gen_number: c_int,
    _context: *mut crate::interfaces::ScanContext,
) {}

extern "C" fn diag_scan_dependent_handles(
    _this: *mut IGCHeapFFI,
    _fn: handle_scan_fn,
    _gen_number: c_int,
    _context: *mut crate::interfaces::ScanContext,
) {}

extern "C" fn diag_descr_generations(
    _this: *mut IGCHeapFFI,
    _fn: gen_walk_fn,
    _context: *mut c_void,
) {}

extern "C" fn diag_trace_gc_segments(_this: *mut IGCHeapFFI) {}

extern "C" fn diag_get_gc_settings(_this: *mut IGCHeapFFI, _settings: *mut EtwGCSettingsInfo) {}

extern "C" fn stress_heap(_this: *mut IGCHeapFFI, _acontext: *mut gc_alloc_context) -> bool {
    false
}

extern "C" fn register_frozen_segment(
    this: *mut IGCHeapFFI,
    pseginfo: *mut segment_info,
) -> segment_handle {
    log!("RegisterFrozenSegment");
    pseginfo
}

extern "C" fn unregister_frozen_segment(_this: *mut IGCHeapFFI, _seg: segment_handle) {}

extern "C" fn is_in_frozen_segment(_this: *mut IGCHeapFFI, _object: *mut Object) -> bool {
    log!("IsInFrozenSegment");
    false
}

#[no_mangle]
extern "C" fn control_events(_this: *mut IGCHeapFFI, _keyword: GCEventKeyword, _level: GCEventLevel) {
    log!("ControlEvents");
}

#[no_mangle]
extern "C" fn control_private_events(
    _this: *mut IGCHeapFFI,
    _keyword: GCEventKeyword,
    _level: GCEventLevel,
) {
    log!("ControlPrivateEvents");
}

extern "C" fn get_generation_with_range(
    _this: *mut IGCHeapFFI,
    _object: *mut Object,
    _ppStart: *mut *mut u8,
    _ppAllocated: *mut *mut u8,
    _ppReserved: *mut *mut u8,
) -> c_uint {
    log!("GetGenerationWithRange");
    0
}

extern "C" fn get_total_pause_duration(_this: *mut IGCHeapFFI) -> i64 {
    log!("GetTotalPauseDuration");
    0
}
extern "C" fn enum_configuration_values(
    _this: *mut IGCHeapFFI,
    _context: *mut c_void,
    _configurationValueFunc: ConfigurationValueFunc,
) {
    log!("EnumConfigurationValues");
}
extern "C" fn update_frozen_segment(
    _this: *mut IGCHeapFFI,
    _seg: segment_handle,
    _allocated: *mut u8,
    _committed: *mut u8,
) {
    log!("UpdateFrozenSegment");
}
extern "C" fn refresh_memory_limit(_this: *mut IGCHeapFFI) -> c_int {
    log!("RefreshMemoryLimit");
    0
}

extern "C" fn enables_no_gc_region_callback_status(
    _this: *mut IGCHeapFFI,
    _callback: *mut NoGCRegionCallbackFinalizerWorkItem,
    _callback_threshold: u64,
) -> enable_no_gc_region_callback_status {
    log!("EnableNoGcRegionCallbackStatus");
    enable_no_gc_region_callback_status::succeed
}

extern "C" fn get_extra_work_for_finalization(_this: *mut IGCHeapFFI) -> *mut FinalizerWorkItem {
    log!("GetExtraWorkForFinalization");
    ptr::null_mut()
}
extern "C" fn get_generation_budget(_this: *mut IGCHeapFFI, _generation: c_int) -> u64 {
    log!("GetGenerationBudget");
    0
}
extern "C" fn get_loh_threshold(_this: *mut IGCHeapFFI) -> usize {
    log!("GetLohThreshold");
    0
}

extern "C" fn diag_walk_heap_with_ac_handling(
    _this: *mut IGCHeapFFI,
    _fn: walk_fn,
    _context: *mut c_void,
    _gen_number: c_int,
    _walk_large_object_heap_p: bool,
) {}

static GCHEAP_VTABLE: IGCHeapVTable = IGCHeapVTable {
    Initialize: heap_initialize,
    Alloc: heap_alloc,
    GarbageCollect: heap_garbage_collect,
    IsValidSegmentSize: is_valid_segment_size,
    IsValidGen0MaxSize: is_valid_gen0_max_size,
    GetValidSegmentSize: get_valid_segment_size,
    SetReservedVMLimit: set_reserved_vm_limit,
    WaitUntilConcurrentGCComplete: wait_until_concurrent_gc_complete,
    IsConcurrentGCInProgress: is_concurrent_gc_in_progress,
    TemporaryEnableConcurrentGC: temporary_enable_concurrent_gc,
    TemporaryDisableConcurrentGC: temporary_disable_concurrent_gc,
    IsConcurrentGCEnabled: is_concurrent_gc_enabled,
    GetMaxGeneration: get_max_generation,
    WhichGeneration: which_generation,
    CollectionCount: collection_count,
    IsPromoted: is_promoted,
    IsHeapPointer: is_heap_pointer,
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