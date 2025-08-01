use crate::gc_handle_manager::MyGCHandleManager;
use crate::interfaces::{
    gc_alloc_context, IGCHeapFFI, IGCHeapVTable, IGCToCLR, Object, ScanContext, HRESULT,
    PER_HEAP_HISTORY, SVR_GC_DATA,
};
use std::ptr::{null_mut, read_unaligned};

#[repr(C)]
pub struct MyGCHeap {
    pub ffi: IGCHeapFFI,
    pub clr_to_gc: *mut IGCToCLR,
    next_alloc_ptr: *mut u8,
    alloc_limit: *mut u8,
    pub handle_manager: Box<MyGCHandleManager>,
}

impl MyGCHeap {
    pub fn new(clr_to_gc: *mut IGCToCLR) -> Self {
        // Allocate a 100MB heap
        const HEAP_SIZE: usize = 100 * 1024 * 1024;
        let mut heap_memory = Vec::with_capacity(HEAP_SIZE);
        let ptr = heap_memory.as_mut_ptr();
        std::mem::forget(heap_memory); // Prevent Rust from freeing the memory

        Self {
            ffi: IGCHeapFFI {
                vtable: &GCHEAP_VTABLE,
            },
            clr_to_gc,
            next_alloc_ptr: ptr,
            alloc_limit: unsafe { ptr.add(HEAP_SIZE) },
            handle_manager: Box::new(MyGCHandleManager::new()),
        }
    }

    pub fn initialize_impl(&mut self) -> HRESULT {
        log!("InitializeImpl called");
        // In a real GC, we'd set up heap segments, thread contexts, etc.
        // For this example, most of the setup is done in `new`.
        0 // S_OK
    }

    // The core allocation logic.
    pub fn alloc_impl(
        &mut self,
        acontext: &mut gc_alloc_context,
        size: usize,
        flags: u32,
    ) -> *mut Object {
        let align = std::mem::size_of::<usize>();
        let mut alloc_size = size + align;
        if let Some(mut mt) = unsafe { (acontext.alloc_ptr as *mut *mut u8).as_mut() } {
            let obj = self.next_alloc_ptr;
            let new_next_alloc_ptr = unsafe { self.next_alloc_ptr.add(alloc_size) };
            if new_next_alloc_ptr > self.alloc_limit {
                return null_mut();
            }
            self.next_alloc_ptr = new_next_alloc_ptr;
            return obj as *mut Object;
        }
        null_mut()
    }
}

// --- IGCHeap VTable ---

extern "C" fn heap_is_promoted(this: *mut IGCHeapFFI, object: *mut Object) -> bool {
    log!("IsPromoted");
    false
}

extern "C" fn heap_get_gc_count(this: *mut IGCHeapFFI) -> i32 {
    log!("GetGcCount");
    0
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

// This is the main entry point for a garbage collection.
extern "C" fn heap_garbage_collect_generation(
    this: *mut IGCHeapFFI,
    gen: u32,
    reason: i32,
) -> i32 {
    log!("GarbageCollectGeneration(gen={}, reason={})", gen, reason);
    let heap = unsafe { &mut *(this as *mut MyGCHeap) };
    let clr = unsafe { &*heap.clr_to_gc };

    // 1. Suspend the EE
    log!("Suspending the EE");
    unsafe {
        ((*clr.vtable).SuspendEE)(clr as *const _ as *mut _, 0);
    }

    // 2. Scan Roots
    log!("Scanning roots");
    let mut sc = ScanContext::default();
    unsafe {
        ((*clr.vtable).GcScanRoots)(
            clr as *const _ as *mut _,
            promote_callback,
            gen as i32,
            &mut sc,
        );
    }

    // 3. TODO: The actual collection - sweeping, compacting, etc.
    // For now, we do nothing. The heap just grows.

    // 4. Resume the EE
    log!("Resuming the EE");
    unsafe {
        ((*clr.vtable).ResumeEE)(clr as *const _ as *mut _, true);
    }

    gen as i32 // Return the collected generation
}

// Dummy callback for GcScanRoots
extern "C" fn promote_callback(
    pObject: *mut *mut Object,
    _pSc: *mut ScanContext,
    _dwFlags: u32,
) {
    // In a real GC, we'd check if the object needs to be moved
    // and update its pointer if so.
    // For our simple example, we just log the root.
    log!("Promote callback for object at {:?}", *pObject);
}

// --- Unimplemented Functions ---
// Most of these are for advanced scenarios like multi-heap/server GC,
// performance monitoring, and detailed heap diagnostics.
// We provide simple stubs that log the call and return a default value.

extern "C" fn heap_shutdown(this: *mut IGCHeapFFI) -> bool {
    log!("Shutdown");
    true // Indicate success
}
extern "C" fn heap_get_heap_type() -> i32 {
    log!("GetHeapType");
    0
}

extern "C" fn heap_set_gc_start_event(this: *mut IGCHeapFFI, event: usize) {
    log!("SetGcStartEvent");
}
extern "C" fn heap_set_gc_end_event(this: *mut IGCHeapFFI, event: usize) {
    log!("SetGcEndEvent");
}
extern "C" fn heap_get_per_heap_history(
    this: *mut IGCHeapFFI,
    heap_history: *mut PER_HEAP_HISTORY,
) {
    log!("GetPerHeapHistory");
}
extern "C" fn heap_get_gc_data_per_heap(
    this: *mut IGCHeapFFI,
    per_heap_data: *mut SVR_GC_DATA,
) {
    log!("GetGCDataPerHeap");
}

extern "C" fn heap_initialize(this: *mut IGCHeapFFI) -> HRESULT {
    let heap = unsafe { &mut *(this as *mut MyGCHeap) };
    heap.initialize_impl()
}

extern "C" fn set_card_table(this: *mut IGCHeapFFI, card_table: *mut u8, card_size: u32) {
    log!("SetCardTable");
}

extern "C" fn enumerate_survivors_of_last_gc(
    this: *mut IGCHeapFFI,
    survivor_walk_fn: extern "C" fn(arg1: *mut Object),
) {
    log!("EnumerateSurvivorsOfLastGC");
}

extern "C" fn verify_heap(this: *mut IGCHeapFFI) -> i32 {
    log!("VerifyHeap");
    0
}

extern "C" fn get_condemned_generation(this: *mut IGCHeapFFI) -> u32 {
    log!("GetCondemnedGeneration");
    0
}

extern "C" fn is_in_condemned_generations(
    this: *mut IGCHeapFFI,
    obj: *mut Object,
    gen: *mut u32,
) -> bool {
    log!("IsInCondemnedGenerations");
    false
}

extern "C" fn get_generation(this: *mut IGCHeapFFI, obj: *mut Object) -> u32 {
    log!("GetGeneration");
    0
}

extern "C" fn get_loh_generation(this: *mut IGCHeapFFI) -> u32 {
    log!("GetLOHGeneration");
    2
}

extern "C" fn get_generation_table(
    this: *mut IGCHeapFFI,
    starts: *mut *mut u8,
    ends: *mut *mut u8,
    ephemerals: *mut *mut u8,
) -> i32 {
    log!("GetGenerationTable");
    0
}

extern "C" fn get_generation_boundaries(
    this: *mut IGCHeapFFI,
    gen: u32,
    start: *mut *mut u8,
    end: *mut *mut u8,
    eff_end: *mut *mut u8,
) -> bool {
    log!("GetGenerationBoundaries");
    false
}

extern "C" fn wait_for_gc_done(this: *mut IGCHeapFFI) -> i32 {
    log!("WaitForGcDone");
    0
}

extern "C" fn get_gc_done_event(this: *mut IGCHeapFFI) -> usize {
    log!("GetGcDoneEvent");
    0
}

extern "C" fn get_number_of_heaps() -> u32 {
    log!("GetNumberOfHeaps");
    1 // We are a single-heap GC
}

extern "C" fn get_heap(this: *mut IGCHeapFFI, heap_index: u32) -> *mut IGCHeapFFI {
    log!("GetHeap");
    this
}

extern "C" fn is_thread_using_alloc_context(this: *mut IGCHeapFFI) -> bool {
    log!("IsThreadUsingAllocContext");
    true
}

extern "C" fn is_valid_segment_pointer(this: *mut IGCHeapFFI, object: *mut Object) -> bool {
    log!("IsValidSegmentPointer");
    false
}

extern "C" fn is_valid_object_pointer(this: *mut IGCHeapFFI, object: *mut Object) -> bool {
    log!("IsValidObjectPointer");
    true
}

extern "C" fn get_next_object(this: *mut IGCHeapFFI, object: *mut Object) -> *mut Object {
    log!("GetNextObject");
    null_mut()
}

extern "C" fn get_size(this: *mut IGCHeapFFI, object: *mut Object) -> usize {
    log!("GetSize");
    unsafe { read_unaligned((object as *mut usize).offset(-1)) }
}

extern "C" fn sync_for_finalization(this: *mut IGCHeapFFI) {
    log!("SyncForFinalization");
}

extern "C" fn get_finalizable_objects(
    this: *mut IGCHeapFFI,
    finalizable_objects: *mut *mut Object,
    count: *mut i32,
) -> bool {
    log!("GetFinalizableObjects");
    false
}

extern "C" fn set_gc_stress_level(this: *mut IGCHeapFFI, level: i32) -> bool {
    log!("SetGcStressLevel");
    false
}

extern "C" fn set_gc_type(this: *mut IGCHeapFFI, is_concurrent: bool, is_compacting: bool) {
    log!("SetGcType");
}

extern "C" fn get_max_generation() -> u32 {
    log!("GetMaxGeneration");
    2
}

extern "C" fn set_promotion_for_thread(this: *mut IGCHeapFFI, promote: bool) {
    log!("SetPromotionForThread");
}

extern "C" fn set_alloc_context_limits(
    this: *mut IGCHeapFFI,
    alloc_limit_new: usize,
    alloc_limit_old: usize,
) {
    log!("SetAllocContextLimits");
}

extern "C" fn get_promote_care(
    this: *mut IGCHeapFFI,
    obj: *mut Object,
    gen: u32,
    must_promote: *mut bool,
) -> bool {
    log!("GetPromoteCare");
    false
}

extern "C" fn start_no_gc_region(this: *mut IGCHeapFFI, total_size: usize, loh_size: usize, disallow_full_blocking_gc: bool) -> i32 {
    log!("StartNoGCRegion");
    0
}

extern "C" fn end_no_gc_region(this: *mut IGCHeapFFI) -> i32 {
    log!("EndNoGCRegion");
    0
}

extern "C" fn get_total_bytes_in_use(this: *mut IGCHeapFFI) -> usize {
    log!("GetTotalBytesInUse");
    0
}

extern "C" fn is_large_object(this: *mut IGCHeapFFI, obj: *mut Object) -> bool {
    log!("IsLargeObject");
    false
}

extern "C" fn get_memory_info(
    this: *mut IGCHeapFFI,
    total_committed: *mut u64,
    total_reserved: *mut u64,
) {
    log!("GetMemoryInfo");
}

extern "C" fn is_server_gc() -> bool {
    log!("IsServerGC");
    false
}

extern "C" fn wait_for_full_gc_complete(this: *mut IGCHeapFFI) -> i32 {
    log!("WaitForFullGCComplete");
    0
}

extern "C" fn stress_heap(this: *mut IGCHeapFFI, acontext: *mut gc_alloc_context) -> bool {
    log!("StressHeap");
    false
}

extern "C" fn settings_changed(this: *mut IGCHeapFFI, setting: u32) {
    log!("SettingsChanged");
}

extern "C" fn get_current_mechanisms(this: *mut IGCHeapFFI) -> i32 {
    log!("GetCurrentMechanisms");
    0
}

extern "C" fn register_for_full_gc_notification(this: *mut IGCHeapFFI, gen: u32, count: u32) -> bool {
    log!("RegisterForFullGCNotification");
    false
}

extern "C" fn cancel_full_gc_notification(this: *mut IGCHeapFFI) -> bool {
    log!("CancelFullGCNotification");
    false
}

extern "C" fn get_next_full_gc_notification(
    this: *mut IGCHeapFFI,
    timeout_milliseconds: i32,
    count: u32,
) -> i32 {
    log!("GetNextFullGCNotification");
    0
}

extern "C" fn control_bgc(this: *mut IGCHeapFFI, suspended: bool) -> bool {
    log!("ControlBGC");
    false
}

extern "C" fn collect_published_editions(this: *mut IGCHeapFFI, gen_number: *mut u32) -> bool {
    log!("CollectPublishedEditions");
    false
}

extern "C" fn get_gen_from_highest_fgc(this: *mut IGCHeapFFI) -> i32 {
    log!("GetGenFromHighestFGC");
    0
}

extern "C" fn get_collected_count(this: *mut IGCHeapFFI, gen: u32) -> i32 {
    log!("GetCollectedCount");
    0
}

extern "C" fn is_gc_running(this: *mut IGCHeapFFI) -> bool {
    log!("IsGCRunning");
    false
}

static GCHEAP_VTABLE: IGCHeapVTable = IGCHeapVTable {
    IsPromoted: heap_is_promoted,
    GetGcCount: heap_get_gc_count,
    Alloc: heap_alloc,
    GarbageCollectGeneration: heap_garbage_collect_generation,
    Shutdown: heap_shutdown,
    GetHeapType: heap_get_heap_type,
    SetGcStartEvent: heap_set_gc_start_event,
    SetGcEndEvent: heap_set_gc_end_event,
    GetPerHeapHistory: heap_get_per_heap_history,
    GetGCDataPerHeap: heap_get_gc_data_per_heap,
    Initialize: heap_initialize,
    SetCardTable: set_card_table,
    EnumerateSurvivorsOfLastGC: enumerate_survivors_of_last_gc,
    VerifyHeap: verify_heap,
    GetCondemnedGeneration: get_condemned_generation,
    IsInCondemnedGenerations: is_in_condemned_generations,
    GetGeneration: get_generation,
    GetLOHGeneration: get_loh_generation,
    GetGenerationTable: get_generation_table,
    GetGenerationBoundaries: get_generation_boundaries,
    WaitForGcDone: wait_for_gc_done,
    GetGcDoneEvent: get_gc_done_event,
    GetNumberOfHeaps: get_number_of_heaps,
    GetHeap: get_heap,
    IsThreadUsingAllocContext: is_thread_using_alloc_context,
    IsValidSegmentPointer: is_valid_segment_pointer,
    IsValidObjectPointer: is_valid_object_pointer,
    GetNextObject: get_next_object,
    GetSize: get_size,
    SyncForFinalization: sync_for_finalization,
    GetFinalizableObjects: get_finalizable_objects,
    SetGcStressLevel: set_gc_stress_level,
    SetGcType: set_gc_type,
    GetMaxGeneration: get_max_generation,
    SetPromotionForThread: set_promotion_for_thread,
    SetAllocContextLimits: set_alloc_context_limits,
    GetPromoteCare: get_promote_care,
    StartNoGCRegion: start_no_gc_region,
    EndNoGCRegion: end_no_gc_region,
    GetTotalBytesInUse: get_total_bytes_in_use,
    IsLargeObject: is_large_object,
    GetMemoryInfo: get_memory_info,
    IsServerGC: is_server_gc,
    WaitForFullGCComplete: wait_for_full_gc_complete,
    StressHeap: stress_heap,
    SettingsChanged: settings_changed,
    GetCurrentMechanisms: get_current_mechanisms,
    RegisterForFullGCNotification: register_for_full_gc_notification,
    CancelFullGCNotification: cancel_full_gc_notification,
    GetNextFullGCNotification: get_next_full_gc_notification,
    ControlBGC: control_bgc,
    CollectPublishedEditions: collect_published_editions,
    GetGenFromHighestFGC: get_gen_from_highest_fgc,
    GetCollectedCount: get_collected_count,
    IsGCRunning: is_gc_running,
};
