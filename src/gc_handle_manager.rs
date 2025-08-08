use crate::gc_handle_store::MyGCHandleStore;
use crate::interfaces::{
    HandleType, IGCHandleManagerFFI, IGCHandleManagerVTable, IGCHandleStoreFFI, Object,
    OBJECTHANDLE, HANDLESCANPROC,
};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

// Global handle store, mimicking the C++ implementation's g_gcGlobalHandleStore.
static mut GLOBAL_HANDLE_STORE: *mut MyGCHandleStore = ptr::null_mut();

#[repr(C)]
pub struct MyGCHandleManager {
    pub ffi: IGCHandleManagerFFI,
    // The manager no longer owns the store directly; it's accessed via the global pointer.
}

impl MyGCHandleManager {
    pub(crate) fn new() -> Self {
        Self {
            ffi: IGCHandleManagerFFI {
                vtable: &GCHANDLEMANAGER_VTABLE,
            },
        }
    }
}

// --- IGCHandleManager VTable ---

extern "C" fn mgr_initialize(_this: *mut IGCHandleManagerFFI) -> bool {
    // Allocate the global handle store, mirroring the C++ Initialize method.
    unsafe {
        if GLOBAL_HANDLE_STORE.is_null() {
            let store = Box::new(MyGCHandleStore::new());
            GLOBAL_HANDLE_STORE = Box::into_raw(store);
        }
    }
    true
}

extern "C" fn mgr_shutdown(_this: *mut IGCHandleManagerFFI) {
    // In a real application, we would deallocate GLOBAL_HANDLE_STORE here.
    // The C++ version is also a no-op, so we match that.
}

#[no_mangle]
extern "C" fn mgr_get_global_handle_store(
    _this: *mut IGCHandleManagerFFI,
) -> *mut IGCHandleStoreFFI {
    unsafe {
        // Return a pointer to the FFI interface of the global store.
        if GLOBAL_HANDLE_STORE.is_null() {
            return ptr::null_mut();
        }
        &mut (*GLOBAL_HANDLE_STORE).ffi
    }
}

extern "C" fn mgr_create_handle_store(_this: *mut IGCHandleManagerFFI) -> *mut IGCHandleStoreFFI {
    // Matches C++: return nullptr
    ptr::null_mut()
}

extern "C" fn mgr_destroy_handle_store(
    _this: *mut IGCHandleManagerFFI,
    _store: *mut IGCHandleStoreFFI,
) {
    // Matches C++: no-op
}

#[no_mangle]
extern "C" fn mgr_create_global_handle_of_type(
    _this: *mut IGCHandleManagerFFI,
    object: *mut Object,
    type_: HandleType,
) -> OBJECTHANDLE {
    // Directly call the global store's creation method, matching C++.
    unsafe {
        if GLOBAL_HANDLE_STORE.is_null() {
            return ptr::null_mut();
        }
        (*GLOBAL_HANDLE_STORE).create_handle_of_type_impl(object, type_)
    }
}

extern "C" fn mgr_create_duplicate_handle(
    _this: *mut IGCHandleManagerFFI,
    _handle: OBJECTHANDLE,
) -> OBJECTHANDLE {
    // Matches C++: return OBJECTHANDLE()
    ptr::null_mut()
}

extern "C" fn mgr_destroy_handle_of_type(
    _this: *mut IGCHandleManagerFFI,
    _handle: OBJECTHANDLE,
    _type_: HandleType,
) {
    // Matches C++: no-op
}

extern "C" fn mgr_destroy_handle_of_unknown_type(
    _this: *mut IGCHandleManagerFFI,
    _handle: OBJECTHANDLE,
) {
    // Matches C++: no-op
}

extern "C" fn mgr_set_extra_info_for_handle(
    _this: *mut IGCHandleManagerFFI,
    _handle: OBJECTHANDLE,
    _type_: HandleType,
    _pExtraInfo: *mut c_void,
) {
    // Matches C++: no-op
}

extern "C" fn mgr_get_extra_info_from_handle(
    _this: *mut IGCHandleManagerFFI,
    _handle: OBJECTHANDLE,
) -> *mut c_void {
    // Matches C++: return nullptr
    ptr::null_mut()
}

extern "C" fn mgr_store_object_in_handle(
    _this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    object: *mut Object,
) {
    // Direct pointer write, matching C++.
    unsafe {
        *(handle as *mut *mut Object) = object;
    }
}

extern "C" fn mgr_store_object_in_handle_if_null(
    _this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    object: *mut Object,
) -> bool {
    // Matches the non-thread-safe C++ implementation.
    unsafe {
        let handle_ptr = handle as *mut *mut Object;
        if (*handle_ptr).is_null() {
            *handle_ptr = object;
            return true;
        }
    }
    false
}

extern "C" fn mgr_set_dependent_handle_secondary(
    _this: *mut IGCHandleManagerFFI,
    _handle: OBJECTHANDLE,
    _object: *mut Object,
) {
    // Matches C++: no-op
}

extern "C" fn mgr_get_dependent_handle_secondary(
    _this: *mut IGCHandleManagerFFI,
    _handle: OBJECTHANDLE,
) -> *mut Object {
    // Matches C++: return nullptr
    ptr::null_mut()
}

extern "C" fn mgr_interlocked_compare_exchange_object_in_handle(
    _this: *mut IGCHandleManagerFFI,
    handle: OBJECTHANDLE,
    object: *mut Object,
    comparand_object: *mut Object,
) -> *mut Object {
    // Use AtomicPtr for a thread-safe implementation, which is an improvement
    // over the non-thread-safe C++ stub.
    let atomic_handle_ptr = handle as *mut AtomicPtr<Object>;
    unsafe {
        (*atomic_handle_ptr)
            .compare_exchange(
                comparand_object,
                object,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .unwrap_or_else(|v| v) // Return the value, whether exchange happened or not
    }
}

extern "C" fn mgr_handle_fetch_type(
    _this: *mut IGCHandleManagerFFI,
    _handle: OBJECTHANDLE,
) -> HandleType {
    // Matches C++: return HandleType() which is equivalent to the default.
    HandleType::default()
}

extern "C" fn mgr_trace_ref_counted_handles(
    _this: *mut IGCHandleManagerFFI,
    _callback: HANDLESCANPROC,
    _param1: usize,
    _param2: usize,
) {
    // Matches C++: no-op
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
    TraceRefCountedHandles: mgr_trace_ref_counted_handles,
};