use crate::gc_handle_manager::MyGCHandleManager;
use crate::gc_handle_store::MAX_HANDLES;
use crate::interfaces::{
    enable_no_gc_region_callback_status, gc_alloc_context, walk_fn, walk_fn2, walk_surv_type,
    ConfigurationValueFunc, EtwGCSettingsInfo, FinalizerWorkItem, GCEventKeyword, GCEventLevel,
    HRESULT, IGCHeapFFI, IGCHeapVTable, IGCToCLR, NoGCRegionCallbackFinalizerWorkItem,
    Object, WriteBarrierOp, WriteBarrierParameters, fq_scan_fn, fq_walk_fn, gen_walk_fn,
    handle_scan_fn, record_surv_fn, segment_handle, segment_info,
};
use std::alloc::{alloc_zeroed, Layout};
use std::ffi::{c_float, c_uint, c_void};
use std::os::raw::c_int;
use std::ptr;
use std::ptr::null_mut;

#[repr(C)]
pub struct MyGCHeap {
    pub ffi: IGCHeapFFI,
    pub clr_to_gc: *mut IGCToCLR,
    pub handle_manager: Box<MyGCHandleManager>,
    card_table: *mut u8,
    heap_start: *mut u8,
    heap_end: *mut u8,
    next_alloc: *mut u8, // <-- The global bump pointer
}

impl MyGCHeap {
    pub(crate) fn new(clr_to_gc: *mut IGCToCLR) -> Self {
        const CARD_SIZE: usize = 512;
        let card_table_size = 10 * 1024 * 1024 / CARD_SIZE;
        let card_table_memory = unsafe {
            std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align_unchecked(card_table_size, 8))
        };
        if card_table_memory.is_null() {
            panic!("[MyGCHeap] Failed to allocate the card table!");
        }
        Self {
            ffi: IGCHeapFFI {
                vtable: &GCHEAP_VTABLE,
            },
            clr_to_gc,
            handle_manager: Box::new(MyGCHandleManager::new()),
            card_table: card_table_memory,
            heap_start: 0_usize as *mut u8,
            heap_end: 0_usize as *mut u8,
            next_alloc: 0_usize as *mut u8,
        }
    }

    // The actual implementation of Initialize
    #[no_mangle]
    pub(crate) fn initialize_impl(&mut self) -> HRESULT {
        log!("Initialize called");

        // Allocate the handle store now that the runtime is ready.
        let layout =
            std::alloc::Layout::array::<*mut crate::interfaces::Object>(MAX_HANDLES).unwrap();
        let store_ptr =
            unsafe { std::alloc::alloc_zeroed(layout) as *mut *mut crate::interfaces::Object };
        if store_ptr.is_null() {
            panic!("Failed to allocate memory for handle store");
        }
        self.handle_manager.store.store = store_ptr;
        log!("GCHandleStore allocated at: {:p}", store_ptr);

        // Allocate memory for the mock heap and card table.
        // In a real application, this memory would be managed more carefully.
        // let mut mock_heap = vec![0u8; MOCK_HEAP_SIZE];
        // let mut mock_card_table = vec![0u8; MOCK_CARD_TABLE_SIZE];
        // 
        // // 3. Get the pointers to the boundaries of your mock heap.
        // let lowest_address = mock_heap.as_mut_ptr();
        // let highest_address = unsafe { lowest_address.add(MOCK_HEAP_SIZE) };
        let MOCK_HEAP_SIZE = 10 * 1024 * 1024;
        let mut mock_heap = vec![0u8; MOCK_HEAP_SIZE];
        let lowest_address = mock_heap.as_mut_ptr();
        self.heap_start = lowest_address;
        self.heap_end = unsafe { lowest_address.add(MOCK_HEAP_SIZE) };
        self.next_alloc = lowest_address;

        // Set up write barrier parameters to match C# implementation, effectively disabling it.
        let params = WriteBarrierParameters {
            operation: WriteBarrierOp::Initialize,
            is_runtime_suspended: true,
            requires_upper_bounds_check: false, // Ignored for Initialize operation
            card_table: self.card_table,
            card_bundle_table: std::ptr::null_mut(),
            lowest_address: !0_usize as *mut u8,
            highest_address: !10000_usize as *mut u8,
            // C# sets ephemeral_low to ~0 (all bits set) to disable write barriers
            ephemeral_low: !0_usize as *mut u8, // Equivalent to (byte*)(~0) in C#
            ephemeral_high: !10000_usize as *mut u8,
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

    pub(crate) fn alloc_impl(
        &mut self,
        acontext: &mut gc_alloc_context,
        size: usize,
        _flags: u32,
    ) -> *mut Object {
        // The original C# code does not show alignment, but it's good practice.
        const ALIGNMENT: usize = 8;
        let aligned_size = (size + (ALIGNMENT - 1)) & !(ALIGNMENT - 1);

        let result = acontext.alloc_ptr;
        let advance = unsafe { result.add(aligned_size) };

        if advance <= acontext.alloc_limit {
            acontext.alloc_ptr = advance;
            return result as *mut Object;
        }

        // If the allocation in the current context fails, allocate a new block of memory.
        const BEGIN_GAP: usize = 24;
        const GROWTH_SIZE: usize = 16 * 1024 * 1024;

        // Ensure the new allocation is large enough for the requested size.
        let allocation_size = if aligned_size + BEGIN_GAP > GROWTH_SIZE {
            aligned_size + BEGIN_GAP
        } else {
            GROWTH_SIZE
        };

        let layout = match Layout::from_size_align(allocation_size, ALIGNMENT) {
            Ok(l) => l,
            Err(_) => {
                eprintln!("[MyRustGC] FATAL: Failed to create memory layout!");
                return ptr::null_mut();
            }
        };

        let new_pages = unsafe { alloc_zeroed(layout) };

        if new_pages.is_null() {
            eprintln!("[MyRustGC] FATAL: Out of memory!");
            return ptr::null_mut();
        }

        let allocation_start = unsafe { new_pages.add(BEGIN_GAP) };
        acontext.alloc_ptr = unsafe { allocation_start.add(aligned_size) };
        acontext.alloc_limit = unsafe { new_pages.add(allocation_size) };

        allocation_start as *mut Object
    }

    pub(crate) fn garbage_collect_impl(&mut self, generation: i32) -> HRESULT {
        log!("GarbageCollect called for generation {}", generation);
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

extern "C" fn register_for_full_gc_notification(this: *mut IGCHeapFFI, gen: u32, count: u32) -> bool {
    log!("RegisterForFullGCNotification");
    false
}

extern "C" fn cancel_full_gc_notification(this: *mut IGCHeapFFI) -> bool {
    log!("CancelFullGCNotification");
    false
}


extern "C" fn wait_for_full_gc_approach(
    this: *mut IGCHeapFFI,
    millisecondsTimeout: c_int,
) -> c_int {
    log!("WaitForFullGCApproach");
    0
}

extern "C" fn wait_for_full_gc_complete(
    this: *mut IGCHeapFFI,
    millisecondsTimeout: c_int,
) -> c_int {
    log!("WaitForFullGCComplete");
    0
}

extern "C" fn which_generation(this: *mut IGCHeapFFI, obj: *mut Object) -> c_uint {
    log!("which_generation");
    0
}

extern "C" fn collection_count(
    this: *mut IGCHeapFFI,
    generation: c_int,
    get_bgc_fgc_coutn: c_int,
) -> c_int {
    log!("collection_count");
    0
}

extern "C" fn start_no_gc_region(
    this: *mut IGCHeapFFI,
    totalSize: u64,
    lohSizeKnown: bool,
    lohSize: u64,
    disallowFullBlockingGC: bool,
) -> c_int {
    log!("start_no_gc_region");
    0
}

extern "C" fn end_no_gc_region(this: *mut IGCHeapFFI) -> c_int {
    log!("end_no_gc_region");
    0
}

extern "C" fn get_total_bytes_in_use(this: *mut IGCHeapFFI) -> usize {
    log!("get_total_bytes_in_use");
    0
}

extern "C" fn get_total_allocated_bytes(this: *mut IGCHeapFFI) -> u64 {
    log!("get_total_allocated_bytes");
    0
}

extern "C" fn garbage_collect(
    this: *mut IGCHeapFFI,
    generation: c_int,
    low_memory_p: bool,
    mode: c_int,
) -> HRESULT {
    log!("garbage_collect");
    0
}

extern "C" fn get_max_generation(this: *mut IGCHeapFFI) -> c_uint {
    log!("GetMaxGeneration");
    2 // C# returns 2, representing generations 0, 1, and 2
}

extern "C" fn set_finalization_run(this: *mut IGCHeapFFI, obj: *mut Object) {
    log!("set_finalization_run");
}

extern "C" fn register_for_finalization(
    this: *mut IGCHeapFFI,
    gen: c_int,
    obj: *mut Object,
) -> bool {
    log!("RegisterForFinalization");
    false
}

extern "C" fn get_last_gc_percent_time_in_gc(this: *mut IGCHeapFFI) -> c_int {
    log!("get_last_gc_percent_time_in_gc");
    0
}

extern "C" fn get_last_gc_generation_size(this: *mut IGCHeapFFI, gen: c_int) -> usize {
    log!("get_last_gc_generation_size");
    0
}

// Misc VM routines
extern "C" fn initialize(this: *mut IGCHeapFFI) -> HRESULT {
    log!("Initialize");
    0
}

extern "C" fn is_promoted(this: *mut IGCHeapFFI, object: *mut Object) -> bool {
    log!("is_promoted");
    false
}

#[no_mangle]
extern "C" fn is_heap_pointer(
    this: *mut IGCHeapFFI,
    object: *mut c_void,
    small_heap_only: bool,
) -> bool {
    log!("is_heap_pointer");
    !object.is_null()
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
    true
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
    context: *mut crate::interfaces::ScanContext,
) {
    log!("DiagScanFinalizeQueue");
}

extern "C" fn diag_scan_handles(
    this: *mut IGCHeapFFI,
    fn_: handle_scan_fn,
    gen_number: c_int,
    context: *mut crate::interfaces::ScanContext,
) {
    log!("DiagScanHandles");
}

extern "C" fn diag_scan_dependent_handles(
    this: *mut IGCHeapFFI,
    fn_: handle_scan_fn,
    gen_number: c_int,
    context: *mut crate::interfaces::ScanContext,
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
#[no_mangle]
extern "C" fn control_events(this: *mut IGCHeapFFI, keyword: GCEventKeyword, level: GCEventLevel) {
    log!("control_events")
}

#[no_mangle]
extern "C" fn control_private_events(
    this: *mut IGCHeapFFI,
    keyword: GCEventKeyword,
    level: GCEventLevel,
) {
    log!("calling control_private_events")
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
