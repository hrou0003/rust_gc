use crate::interfaces::{
    HandleType, IGCHandleStoreFFI, IGCHandleStoreVTable, Object, OBJECTHANDLE,
};
use std::ffi::c_void;
use std::os::raw::c_int;
use std::sync::atomic::{AtomicIsize, Ordering};

pub const MAX_HANDLES: usize = 65535; // Match C# implementation

/// Simple handle store using pointer array like the C# implementation
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
        Self {
            ffi: IGCHandleStoreFFI {
                vtable: &GCHANDLESTORE_VTABLE,
            },
            store: std::ptr::null_mut(),
            handle_count: AtomicIsize::new(0),
        }
    }

    // Implementation matching C# CreateHandleOfType
    pub(crate) fn create_handle_of_type_impl(
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
    pub(crate) fn create_handle_with_extra_info_impl(
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
    pub(crate) fn contains_handle_impl(&self, handle: OBJECTHANDLE) -> bool {
        log!("GCHandleStore ContainsHandle");
        let handle_ptr = handle as *const *mut Object;
        let start = self.store as *const *mut Object;
        let count = self.handle_count.load(Ordering::SeqCst) as usize;
        let end = unsafe { start.add(count) };
        handle_ptr >= start && handle_ptr < end
    }

    // Match C# DumpHandles implementation
    pub(crate) fn dump_handles_impl(&self) {
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
    pub(crate) fn uproot_impl(&mut self) {
        log!("GCHandleStore Uproot");
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
