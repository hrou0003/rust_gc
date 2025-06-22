# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a custom .NET Garbage Collector implementation written in Rust that integrates with the .NET runtime through FFI (Foreign Function Interface). The project demonstrates how to build a pluggable GC that can replace the default .NET garbage collector.

## Build Commands

**Rust Library (GC Implementation):**
```bash
cargo build          # Debug build
cargo build --release # Release build
```

**C# Test Application:**
```bash
cd test/TestApp
dotnet build         # Build test app
dotnet run           # Run test app with default GC
```

**To test with custom GC:**
The Rust library must be built as a cdylib and placed where the .NET runtime can find it. Set environment variables to configure GC:
```bash
export DOTNET_gcServer=0  # Disable server GC (required)
export DOTNET_GCName=/path/to/librust_gc.dylib  # Path to custom GC
```

## Architecture

### Core Components

**FFI Interface Layer (`src/interfaces.rs`):**
- Defines C-compatible structs and function pointers for .NET GC interface
- Contains VTable definitions for IGCHeap, IGCHandleManager, and IGCHandleStore
- Provides type-safe Rust bindings for gcinterface.h equivalents

**Data Types (`src/types.rs`):**
- Core GC data structures (ObjectHandle, WriteBarrierParameters, gc_alloc_context)
- Enums for handle types, GC events, and operation modes
- Bitflag definitions using the `bitflags` crate

**Main Implementation (`src/lib.rs`):**
- `MyGCHeap`: Primary GC implementation with allocation contexts and write barriers
- `MyGCHandleManager`: Manages object handles and their lifecycles  
- `MyGCHandleStore`: Storage backend for handles with atomic operations
- VTable implementations that bridge Rust methods to C function pointers
- `GC_Initialize` export function that .NET runtime calls to bootstrap the GC

### Key Design Patterns

**VTable Pattern:**
Each interface (IGCHeap, IGCHandleManager, IGCHandleStore) uses a VTable pattern where Rust structs contain a VTable pointer as their first field, enabling C++ virtual function calls from .NET.

**Handle Management:**
Objects are tracked through handles stored in a pre-allocated array. Handles contain object pointers, type information, and extra data. Atomic operations ensure thread safety.

**Memory Allocation:**
Uses allocation contexts for efficient object allocation. Large allocations get new memory chunks, small allocations use existing context space.

**Write Barriers:**
Implements write barrier stomping to disable/configure generational GC write barriers based on runtime requirements.

### FFI Safety Considerations

- All exported functions use `extern "C"` calling convention
- Structs use `#[repr(C)]` for C-compatible memory layout
- Raw pointers are used extensively for C interop
- Memory management follows .NET GC ownership rules
- VTable function pointers must match exact C++ signatures

### Testing Architecture

The C# test application in `test/TestApp/` exercises various GC scenarios:
- Small object allocation (SOH - Small Object Heap)
- Large object allocation (LOH - Large Object Heap) 
- GC handle creation/destruction (Normal, Weak, Pinned)
- Forced garbage collection cycles
- Memory statistics tracking

## References

**Related Implementation:**
- [ManagedDotnetGC](https://github.com/kevingosse/ManagedDotnetGC) - A C# implementation of a .NET GC using NativeAOT. This repository provides valuable reference for:
  - Complete .NET GC interface implementation patterns
  - Project structure with separate GC implementation, loader, and test application
  - Alternative approach using C# with NativeAOT instead of Rust FFI
  - Comparative architecture for understanding different GC implementation strategies

This reference implementation can help understand the complete scope of methods that need implementation beyond the current `todo!()` placeholders in this Rust version.

## Development Notes

**Cargo Configuration:**
The library is configured as `crate-type = ["cdylib"]` to produce a dynamic library that .NET can load.

**Rust-to-.NET Integration:**
The GC integrates at the lowest level of .NET's memory management, replacing the built-in GC entirely. This requires implementing dozens of interface methods, most marked as `todo!()` for this example.

**Platform Considerations:**
Calling conventions differ between platforms (x86 uses different conventions than x64). The code accounts for this in function pointer definitions.