using System;
using System.Runtime.InteropServices;

namespace TestApp
{
    class Program
    {
        // Structure to track memory allocations
        class MemoryStats
        {
            public long TotalAllocatedBytes { get; set; }
            public int GcCount { get; set; }
            public int Generation0Count { get; set; }
            public int Generation1Count { get; set; }
            public int Generation2Count { get; set; }
        }

        // Helper method to collect and print memory statistics
        static MemoryStats CollectMemoryStats()
        {
            var stats = new MemoryStats
            {
                TotalAllocatedBytes = GC.GetTotalAllocatedBytes(),
                GcCount = GC.CollectionCount(0) + GC.CollectionCount(1) + GC.CollectionCount(2),
                Generation0Count = GC.CollectionCount(0),
                Generation1Count = GC.CollectionCount(1),
                Generation2Count = GC.CollectionCount(2)
            };
            return stats;
        }

        static void PrintMemoryStats(string message, MemoryStats stats)
        {
            Console.WriteLine($"--- {message} ---");
            Console.WriteLine($"Total Allocated Bytes: {stats.TotalAllocatedBytes:N0}");
            Console.WriteLine($"GC Collections: {stats.GcCount} (Gen0: {stats.Generation0Count}, Gen1: {stats.Generation1Count}, Gen2: {stats.Generation2Count})");
            Console.WriteLine();
        }

        static void Main(string[] args)
        {
            Console.WriteLine("===================================");
            Console.WriteLine("Test Application for Rust GC in .NET");
            Console.WriteLine("===================================");
            Console.WriteLine();

            // Test 1: Allocate a large number of small objects
            var stats1 = CollectMemoryStats();
            PrintMemoryStats("Initial memory state", stats1);

            Console.WriteLine("Test 1: Allocating 10,000 small objects...");
            var list1 = new System.Collections.Generic.List<object>(10_000);
            for (int i = 0; i < 10_000; i++)
            {
                list1.Add(new byte[100]); // Small object, should go into SOH
            }

            var stats2 = CollectMemoryStats();
            PrintMemoryStats("After small object allocations", stats2);

            // Test 2: Force a garbage collection
            Console.WriteLine("Test 2: Forcing a full garbage collection...");
            GC.Collect();

            var stats3 = CollectMemoryStats();
            PrintMemoryStats("After garbage collection", stats3);

            // Test 3: Allocate large objects
            Console.WriteLine("Test 3: Allocating 10 large objects...");
            var list2 = new System.Collections.Generic.List<object>(10);
            for (int i = 0; i < 10; i++)
            {
                list2.Add(new byte[100_000]); // Large object, should go into LOH
            }

            var stats4 = CollectMemoryStats();
            PrintMemoryStats("After large object allocations", stats4);

            // Test 4: Test GC handles
            Console.WriteLine("Test 4: Testing GC handles...");
            var obj = new object();

            // Create different types of handles
            var strongHandle = GCHandle.Alloc(obj, GCHandleType.Normal);
            var weakHandle = GCHandle.Alloc(obj, GCHandleType.Weak);
            var pinnedHandle = GCHandle.Alloc(obj, GCHandleType.Pinned);

            Console.WriteLine($"Created Strong Handle: {strongHandle}");
            Console.WriteLine($"Created Weak Handle: {weakHandle}");
            Console.WriteLine($"Created Pinned Handle: {pinnedHandle}");

            // Test 5: Release some handles and collect again
            Console.WriteLine("Test 5: Releasing handles and collecting...");
            list1 = null; // Release the small objects
            strongHandle.Free();
            weakHandle.Free();
            pinnedHandle.Free();

            GC.Collect();

            var stats5 = CollectMemoryStats();
            PrintMemoryStats("Final memory state", stats5);

            Console.WriteLine("Test completed successfully!");
        }
    }
}
