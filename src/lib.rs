// lib.rs

#![allow(non_snake_case, unused_variables, dead_code)]

// A helper for printing debug messages, like the article's `Write` method
macro_rules! log {
    ($($arg:tt)*) => {
        println!("[MyRustGC] {}", format!($($arg)*))
    };
}

// Import our FFI definitions
mod interfaces;
mod gc_heap;
mod gc_handle_manager;
mod gc_handle_store;

use interfaces::*;

use crate::gc_heap::MyGCHeap;
use std::ffi::{c_uint, c_void};
use std::os::raw::c_int;
use std::ptr::null_mut;

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
        log!("GC_Initialize: Set gc_handle_manager to {:p}", *gc_handle_manager);
        
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
