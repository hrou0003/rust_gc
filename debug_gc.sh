#!/bin/bash

# Debug script for testing the Rust GC implementation
# Based on the CLAUDE.md documentation

echo "=== Rust GC Debugging Script ==="
echo

# Set environment variables for custom GC
export DOTNET_gcServer=0  # Disable server GC (required)
export DOTNET_GCName="$(pwd)/target/release/librust_gc.dylib"

echo "Environment setup:"
echo "DOTNET_gcServer=$DOTNET_gcServer"
echo "DOTNET_GCName=$DOTNET_GCName"
echo

# Check if the library exists
if [ ! -f "$DOTNET_GCName" ]; then
    echo "ERROR: GC library not found at $DOTNET_GCName"
    echo "Make sure to run 'cargo build --release' first"
    exit 1
fi

echo "Library found: $DOTNET_GCName"
echo "Library info:"
file "$DOTNET_GCName"
echo

# Check if test app is built
if [ ! -d "test/TestApp/bin" ]; then
    echo "Building C# test application..."
    cd test/TestApp
    dotnet build
    cd ../..
fi

echo "=== Running C# Test Application with Rust GC ==="
echo "Watch for '[MyRustGC]' log messages..."
echo

# Run the test application
cd test/TestApp
dotnet run

echo
echo "=== Test completed ==="