/*
 * Buffer Overflow Analysis - OOB Access Demonstration
 *
 * This file illustrates the vulnerable memory access patterns
 * that occur due to the slice counter integer overflow
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Memory layout simulation */
typedef struct {
    uint8_t *heap;
    size_t heap_size;
    uint32_t *allocation_map;  /* Track allocated regions */
} MemorySimulator;

typedef struct {
    uint32_t offset;
    uint32_t size;
    char tag[32];
} Allocation;

#define MAX_ALLOCATIONS 256

MemorySimulator *mem_sim_create(size_t heap_size) {
    MemorySimulator *sim = (MemorySimulator *)malloc(sizeof(MemorySimulator));
    if (!sim) return NULL;

    sim->heap = (uint8_t *)malloc(heap_size);
    sim->heap_size = heap_size;

    if (!sim->heap) {
        free(sim);
        return NULL;
    }

    /* Initialize heap with pattern for detection */
    memset(sim->heap, 0xCD, heap_size);  /* 0xCD = uninitialized pattern */

    sim->allocation_map = (uint32_t *)calloc(MAX_ALLOCATIONS, sizeof(Allocation));
    if (!sim->allocation_map) {
        free(sim->heap);
        free(sim);
        return NULL;
    }

    printf("[MEMSIM] Created simulated heap: %zu bytes\n", heap_size);
    return sim;
}

void mem_sim_destroy(MemorySimulator *sim) {
    if (sim) {
        free(sim->heap);
        free(sim->allocation_map);
        free(sim);
    }
}

/*
 * VULNERABLE: Simulate h.264 buffer overflow
 *
 * Demonstrates what happens when slice_count causes integer overflow
 */
void demonstrate_buffer_overflow_vulnerable(void) {
    printf("\n=== VULNERABLE CODE PATH ===\n\n");

    /* Create simulated memory */
    MemorySimulator *mem = mem_sim_create(16384);
    if (!mem) {
        fprintf(stderr, "Failed to create memory simulator\n");
        return;
    }

    /* Scenario: Attacker-controlled slice count */
    uint32_t slice_count = 0x40000000;  /* Very large value */
    size_t entry_size = 16;

    printf("Input: slice_count = 0x%08x (%u)\n", slice_count, slice_count);
    printf("Entry size: %zu bytes\n", entry_size);

    /* VULNERABLE: Integer overflow in capacity calculation */
    size_t capacity = slice_count * entry_size;
    printf("Calculated capacity: 0x%08zx (%zu bytes)\n", capacity, capacity);

    /* Check for overflow */
    if (capacity < slice_count) {
        printf("INTEGER OVERFLOW DETECTED: %u * %zu\n", slice_count, entry_size);
    }

    /* VULNERABLE: Actual allocation is much smaller */
    size_t actual_allocated = 4096;  /* Simulated allocation */
    printf("Actual allocation: %zu bytes (due to overflow)\n", actual_allocated);

    /* Allocate from simulated heap */
    uint8_t *buffer = mem->heap;  /* Use heap simulator */

    printf("\nHeap buffer at offset 0, allocated size: %zu\n", actual_allocated);

    /* VULNERABLE: Write loop that exceeds buffer */
    printf("\n--- Write Operations ---\n");

    uint32_t writes = 0;
    for (uint32_t i = 0; i < slice_count && writes < 1000; i++) {
        size_t offset = i * entry_size;

        /* Write pattern */
        if (offset + entry_size <= actual_allocated) {
            /* Safe write */
            memset(buffer + offset, 0x41 + (i % 26), entry_size);
            if (writes % 256 == 0) {
                printf("[%u] Write to offset 0x%08zx: SAFE\n", i, offset);
            }
            writes++;
        } else {
            /* OOB write */
            printf("[OOB] Write to offset 0x%08zx: OUT OF BOUNDS!\n", offset);
            printf("      Allocated: 0x%08zx, Attempting: 0x%08zx\n",
                   actual_allocated, offset + entry_size);
            printf("      Overflow size: 0x%08zx bytes\n",
                   offset + entry_size - actual_allocated);

            /* This would corrupt heap metadata or adjacent objects */
            break;
        }
    }

    printf("\nHeap corruption pattern:\n");
    printf("- First 4096 bytes: Valid slice data (0x41-0x5A pattern)\n");
    printf("- Bytes 4096+: Out-of-bounds writes corrupt:\n");
    printf("  * Adjacent heap allocations\n");
    printf("  * Heap metadata (size fields, free lists)\n");
    printf("  * Function pointers or other sensitive data\n");

    mem_sim_destroy(mem);
}

/*
 * PATCHED: Demonstrate safe buffer handling
 */
void demonstrate_buffer_overflow_patched(void) {
    printf("\n=== PATCHED CODE PATH ===\n\n");

    MemorySimulator *mem = mem_sim_create(16384);
    if (!mem) {
        fprintf(stderr, "Failed to create memory simulator\n");
        return;
    }

    /* Same attacker input */
    uint32_t slice_count = 0x40000000;
    size_t entry_size = 16;

    printf("Input: slice_count = 0x%08x (%u)\n", slice_count, slice_count);

    /* PATCHED: Validate before calculation */
    #define MAX_SLICES 1024
    if (slice_count > MAX_SLICES) {
        printf("VALIDATION FAILED: slice_count (%u) > MAX_SLICES (%u)\n",
               slice_count, MAX_SLICES);
        printf("Result: Reject malformed input\n");
        printf("Status: SECURE\n");
        mem_sim_destroy(mem);
        return;
    }

    /* PATCHED: Check for overflow before multiplication */
    if (slice_count > SIZE_MAX / entry_size) {
        printf("OVERFLOW CHECK: Multiplication would overflow\n");
        printf("Result: Reject input\n");
        printf("Status: SECURE\n");
        mem_sim_destroy(mem);
        return;
    }

    size_t capacity = slice_count * entry_size;
    printf("Safe capacity calculation: %zu bytes (validated)\n", capacity);
    printf("Result: Input rejected during validation\n");
    printf("Status: SECURE - Buffer overflow prevented\n");

    mem_sim_destroy(mem);
}

/*
 * Compare vulnerability vs patch
 */
void analyze_overflow_pattern(void) {
    printf("\n============================================\n");
    printf("   Buffer Overflow Analysis\n");
    printf("============================================\n");

    printf("\nVulnerability Chain:\n");
    printf("1. Attacker creates malicious h.264 file\n");
    printf("2. slice_count field = 0x40000000 (1GB)\n");
    printf("3. FFmpeg calculates: 0x40000000 * 16 = overflow\n");
    printf("4. malloc receives: ~256MB (overflowed size)\n");
    printf("5. Loop writes: slice[0..1GB] to 256MB buffer\n");
    printf("6. Result: Heap corruption at bytes 256MB+\n");
    printf("7. Impact: Crash, info disclosure, or RCE\n");

    printf("\nPatched Behavior:\n");
    printf("1. Input validation: slice_count <= MAX_SLICES (1024)\n");
    printf("2. Overflow check: SIZE_MAX check before multiply\n");
    printf("3. Malicious input rejected at step 1\n");
    printf("4. Result: SECURE - Buffer overflow prevented\n");
}

/*
 * Memory corruption effects
 */
void visualize_heap_layout(void) {
    printf("\n============================================\n");
    printf("   Heap Layout Before/After Overflow\n");
    printf("============================================\n");

    printf("\nBEFORE OVERFLOW:\n");
    printf("  0x0000 +------------------+\n");
    printf("         | Slice Buffer     |\n");
    printf("         | (4KB allocated)  |\n");
    printf("  0x1000 +------------------+\n");
    printf("         | String Pool      |\n");
    printf("  0x2000 +------------------+\n");
    printf("         | Metadata         |\n");
    printf("  0x3000 +------------------+\n");

    printf("\nAFTER INTEGER OVERFLOW (VULNERABLE):\n");
    printf("  0x0000 +------------------+\n");
    printf("         | Slice Buffer     |\n");
    printf("  0x1000 +==== OOB WRITE ====+ <-- OVERFLOW STARTS\n");
    printf("         | String Pool      |\n");
    printf("         | [CORRUPTED]      | <-- Heap corruption\n");
    printf("  0x2000 +==== OOB WRITE ====+\n");
    printf("         | Metadata         |\n");
    printf("         | [CORRUPTED]      | <-- Vtable/ptr corruption\n");
    printf("  0x3000 +==== OOB WRITE ====+\n");

    printf("\nAFTER PATCHED (SAFE):\n");
    printf("  0x0000 +------------------+\n");
    printf("         | REJECTED INPUT   |\n");
    printf("  (no allocation)\n");
    printf("         | No heap changes  |\n");
    printf("  +------------------+\n");
}

void print_exploitation_scenario(void) {
    printf("\n============================================\n");
    printf("   Exploitation Scenarios\n");
    printf("============================================\n");

    printf("\nScenario 1: INFORMATION DISCLOSURE\n");
    printf("  - OOB read via corrupted pointers\n");
    printf("  - Leak heap addresses\n");
    printf("  - Leak function pointers\n");
    printf("  - Impact: ASLR bypass\n\n");

    printf("Scenario 2: DENIAL OF SERVICE\n");
    printf("  - Corrupt heap metadata\n");
    printf("  - Trigger heap allocator crash\n");
    printf("  - Segfault in free() or malloc()\n");
    printf("  - Impact: DoS via crash\n\n");

    printf("Scenario 3: REMOTE CODE EXECUTION (Complex)\n");
    printf("  - Spray heap with controlled objects\n");
    printf("  - Overwrite object's vtable pointer\n");
    printf("  - Trigger virtual method call\n");
    printf("  - Execute arbitrary code\n");
    printf("  - Impact: Full system compromise\n\n");

    printf("Scenario 4: ARBITRARY MEMORY WRITE\n");
    printf("  - Corrupt next_chunk pointer in heap metadata\n");
    printf("  - Use unlink() macro to write to arbitrary address\n");
    printf("  - Overwrite return address on stack\n");
    printf("  - Execute shellcode\n");
    printf("  - Impact: RCE\n");
}
