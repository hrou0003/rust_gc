use crate::interfaces::{
    HandleType, IGCHandleStoreFFI, IGCHandleStoreVTable, Object, OBJECTHANDLE,
};
use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr;
use std::sync::atomic::{AtomicIsize, Ordering};

pub const MAX_HANDLES: usize = 65535; // Match C++ and C# implementation

/// Simple handle store using a pointer array, matching the C++ ZeroGCHandleStore logic.
#[repr(C)]
pub struct MyGCHandleStore {
    // The FFI interface must be the first field for pointer casting to work.
    pub ffi: IGCHandleStoreFFI,
    // Simple array of object pointers, matching C# nint* _store
    pub(crate) store: *mut *mut Object,
    handle_count: AtomicIsize,
}

impl MyGCHandleStore {
    pub(crate) fn new() -> Self {
        // Allocate a buffer to store handle pointers.
        let mut store_vec: Vec<*mut Object> = Vec::with_capacity(MAX_HANDLES);
        let ptr = store_vec.as_mut_ptr();
        std::mem::forget(store_vec); // Prevent Rust from freeing the memory.

        Self {
            ffi: IGCHandleStoreFFI {
                vtable: &GCHANDLESTORE_VTABLE,
            },
            store: ptr,
            handle_count: AtomicIsize::new(0),
        }
    }

    /// Implements the logic of C++ ZeroGCHandleStore::CreateHandleOfType.
    pub(crate) fn create_handle_of_type_impl(
        &mut self,
        object: *mut Object,
        _type: HandleType,
    ) -> OBJECTHANDLE {
        let index = self.handle_count.fetch_add(1, Ordering::SeqCst);
        if index >= MAX_HANDLES as isize {
            panic!("Too many handles! Limit is {}.", MAX_HANDLES);
        }

        unsafe {
            let handle_slot_ptr = self.store.add(index as usize);
            // Store the object pointer in our array.
            *handle_slot_ptr = object;
            // Return a pointer to the slot, which serves as the handle.
            handle_slot_ptr as OBJECTHANDLE
        }
    }

    /// Implements the logic of C++ ZeroGCHandleStore::CreateDependentHandle.
    pub(crate) fn create_dependent_handle_impl(
        &mut self,
        primary: *mut Object,
        _secondary: *mut Object,
    ) -> OBJECTHANDLE {
        let index = self.handle_count.fetch_add(1, Ordering::SeqCst);
        if index >= MAX_HANDLES as isize {
            panic!("Too many handles! Limit is {}.", MAX_HANDLES);
        }

        unsafe {
            let handle_slot_ptr = self.store.add(index as usize);
            // Store the primary object pointer in our array.
            *handle_slot_ptr = primary;
            // Return a pointer to the slot, which serves as the handle.
            handle_slot_ptr as OBJECTHANDLE
        }
    }

    /// Matches C++ by always returning a null handle.
    pub(crate) fn create_handle_with_extra_info_impl(
        &mut self,
        _object: *mut Object,
        _type: HandleType,
        _extra_info: *mut c_void,
    ) -> OBJECTHANDLE {
        ptr::null_mut()
    }

    /// Matches C++ by always returning false.
    pub(crate) fn contains_handle_impl(&self, _handle: OBJECTHANDLE) -> bool {
        false
    }

    /// Matches C++ empty Uproot implementation.
    pub(crate) fn uproot_impl(&mut self) {
        // Does nothing, just like the C++ version.
    }
}

// --- IGCHandleStore VTable ---

extern "C" fn store_uproot(this: *mut IGCHandleStoreFFI) {
    let store = unsafe { &mut *(this as *mut MyGCHandleStore) };
    store.uproot_impl();
}

extern "C" fn store_contains_handle(this: *mut IGCHandleStoreFFI, handle: OBJECTHANDLE) -> bool {
    let store = unsafe { &*(this as *mut MyGCHandleStore) };
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

// Matches C++ by returning a null handle.
extern "C" fn store_create_handle_affinitized(
    _this: *mut IGCHandleStoreFFI,
    _object: *mut Object,
    _type_: HandleType,
    _heap: c_int,
) -> OBJECTHANDLE {
    ptr::null_mut()
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
    store.create_dependent_handle_impl(primary, secondary)
}

static GCHANDLESTORE_VTABLE: IGCHandleStoreVTable = IGCHandleStoreVTable {
    Uproot: store_uproot,
    ContainsHandle: store_contains_handle,
    CreateHandleOfType: store_create_handle,
    CreateHandleOfType_HeapAffinitized: store_create_handle_affinitized,
    CreateHandleWithExtraInfo: store_create_handle_with_extra,
    CreateDependentHandle: store_create_dependent_handle,
};