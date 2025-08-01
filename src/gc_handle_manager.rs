use crate::gc_handle_store::MyGCHandleStore;
use crate::interfaces::{
    IGCHandleManagerVTable, HandleType, IGCHandleManagerFFI,
    IGCHandleStoreFFI, Object, OBJECTHANDLE, HANDLESCANPROC,
};
use std::ffi::c_void;
use std::sync::atomic::{AtomicIsize, Ordering};

#[repr(C)]
pub struct MyGCHandleManager {
    pub ffi: IGCHandleManagerFFI,
    pub store: Box<MyGCHandleStore>,
}

impl MyGCHandleManager {
    pub(crate) fn new() -> Self {
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
