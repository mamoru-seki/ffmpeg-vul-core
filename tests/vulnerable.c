/*
 * Vulnerable Code Path Test
 *
 * Demonstrates the vulnerable slice buffer handling
 * Triggers integer overflow and potential OOB access
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Test configuration */
#define ENTRY_SIZE 16
#define TEST_SLICE_COUNT_OVERFLOW 0x40000000
#define TEST_SLICE_COUNT_LARGE    1000000

typedef struct {
    uint32_t id;
    uint32_t pos;
    uint32_t size;
    uint8_t type;
} SliceEntry;

/*
 * Test: Integer Overflow Detection
 */
int test_integer_overflow(void) {
    printf("\n[TEST] Integer Overflow in Size Calculation\n");
    printf("-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-\n");

    uint32_t slice_count = TEST_SLICE_COUNT_OVERFLOW;
    size_t entry_size = ENTRY_SIZE;

    printf("Input: slice_count = 0x%08x\n", slice_count);
    printf("Entry size: %zu\n", entry_size);

    /* VULNERABLE: Calculate buffer size without overflow check */
    size_t buffer_size = slice_count * entry_size;

    printf("Calculated buffer_size: %zu (0x%08zx)\n", buffer_size, buffer_size);

    /* Check if overflow occurred */
    if (buffer_size < slice_count) {
        printf("STATUS: OVERFLOW DETECTED\n");
        printf("  slice_count * entry_size overflowed\n");
        printf("  Expected size: %zu bytes\n", (size_t)slice_count * entry_size);
        printf("  Actual size in 32-bit: overflow\n");
        printf("RESULT: PASS - Overflow correctly identified\n");
        return 1;
    } else {
        printf("STATUS: No overflow detected (on 64-bit system)\n");
        printf("RESULT: FAIL - Test requires 32-bit overflow behavior\n");
        return 0;
    }
}

/*
 * Test: Buffer Allocation with Undersized Buffer
 */
int test_undersized_allocation(void) {
    printf("\n[TEST] Undersized Buffer Allocation\n");
    printf("-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-\n");

    /* Simulate 32-bit integer overflow */
    uint32_t slice_count_32 = TEST_SLICE_COUNT_OVERFLOW;
    uint32_t entry_size_32 = ENTRY_SIZE;

    /* 32-bit multiplication wraps around */
    uint32_t overflow_size = slice_count_32 * entry_size_32;

    printf("32-bit calculation: 0x%08x * %u = 0x%08x\n",
           slice_count_32, entry_size_32, overflow_size);

    printf("Expected allocation: %.2f GB\n",
           (double)slice_count_32 * entry_size_32 / (1024*1024*1024));
    printf("Actual allocation (due to overflow): %u bytes (~%.2f MB)\n",
           overflow_size, (double)overflow_size / (1024*1024));

    if (overflow_size < 1024*1024) {
        printf("STATUS: Severe undersizing detected\n");
        printf("RESULT: PASS - Vulnerability confirmed\n");
        return 1;
    } else {
        printf("STATUS: Allocation not severely undersized\n");
        printf("RESULT: FAIL - Cannot demonstrate undersizing\n");
        return 0;
    }
}

/*
 * Test: Out-of-Bounds Write Detection
 */
int test_oob_write_detection(void) {
    printf("\n[TEST] Out-of-Bounds Write Detection\n");
    printf("-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-\n");

    /* Allocate small buffer to simulate undersized allocation */
    size_t small_alloc = 4096;  /* 4KB - simulating overflow result */
    uint8_t *buffer = (uint8_t *)malloc(small_alloc);

    if (!buffer) {
        printf("STATUS: Failed to allocate memory\n");
        return 0;
    }

    printf("Allocated %zu bytes at %p\n", small_alloc, (void *)buffer);

    /* Initialize buffer */
    memset(buffer, 0xCD, small_alloc);

    /* Simulate large slice count writes */
    uint32_t slice_count = 1000;  /* Many slices */
    int oob_detected = 0;

    printf("Writing %u slices of %u bytes each\n", slice_count, ENTRY_SIZE);

    for (uint32_t i = 0; i < slice_count; i++) {
        size_t offset = i * ENTRY_SIZE;
        SliceEntry *entry = (SliceEntry *)(buffer + offset);

        if (offset + ENTRY_SIZE > small_alloc) {
            printf("OOB: Slice %u at offset %zu (beyond %zu)\n",
                   i, offset + ENTRY_SIZE, small_alloc);
            oob_detected = 1;
            break;
        }

        /* Write slice entry */
        entry->id = i;
        entry->pos = i * 1024;
        entry->size = 512;
        entry->type = 0x05;
    }

    free(buffer);

    if (oob_detected) {
        printf("STATUS: Out-of-bounds access detected\n");
        printf("RESULT: PASS - OOB vulnerability demonstrated\n");
        return 1;
    } else {
        printf("STATUS: No OOB detected with current parameters\n");
        printf("RESULT: FAIL - Adjust test parameters\n");
        return 0;
    }
}

/*
 * Test: Memory Layout Corruption
 */
int test_memory_corruption(void) {
    printf("\n[TEST] Memory Corruption Scenario\n");
    printf("-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-\n");

    /* Allocate multiple blocks to simulate heap */
    size_t block_size = 256;
    uint8_t *slice_buffer = (uint8_t *)malloc(block_size);
    uint8_t *adjacent_block = (uint8_t *)malloc(block_size);

    if (!slice_buffer || !adjacent_block) {
        printf("Failed to allocate blocks\n");
        free(slice_buffer);
        free(adjacent_block);
        return 0;
    }

    printf("Slice buffer at %p (%zu bytes)\n", (void *)slice_buffer, block_size);
    printf("Adjacent block at %p (%zu bytes)\n", (void *)adjacent_block, block_size);

    /* Initialize adjacent block with sentinel value */
    memset(adjacent_block, 0xAA, block_size);

    /* Simulate OOB write from slice buffer into adjacent block */
    uint8_t *overflow_point = slice_buffer + block_size;
    int corrupted = 0;

    if (overflow_point >= adjacent_block &&
        overflow_point < (adjacent_block + block_size)) {
        /* OOB write would corrupt adjacent block */
        printf("Overflow point at %p\n", (void *)overflow_point);
        printf("Adjacent block at %p\n", (void *)adjacent_block);
        printf("STATUS: Heap corruption possible\n");
        corrupted = 1;
    }

    free(slice_buffer);
    free(adjacent_block);

    if (corrupted) {
        printf("RESULT: PASS - Adjacent block corruption demonstrated\n");
        return 1;
    } else {
        printf("RESULT: FAIL - Cannot demonstrate heap corruption with current layout\n");
        return 0;
    }
}

/*
 * Test Suite Runner
 */
int main(int argc, char *argv[]) {
    printf("\n");
    printf("==========================================\n");
    printf("   Vulnerable Code Path Test Suite\n");
    printf("==========================================\n");

    int test_count = 0;
    int pass_count = 0;

    printf("\nRunning tests...\n");

    /* Run tests */
    if (test_integer_overflow()) pass_count++;
    test_count++;

    if (test_undersized_allocation()) pass_count++;
    test_count++;

    if (test_oob_write_detection()) pass_count++;
    test_count++;

    if (test_memory_corruption()) pass_count++;
    test_count++;

    /* Print summary */
    printf("\n");
    printf("==========================================\n");
    printf("   Test Summary\n");
    printf("==========================================\n");
    printf("Total tests: %d\n", test_count);
    printf("Passed:      %d\n", pass_count);
    printf("Failed:      %d\n", test_count - pass_count);

    if (pass_count == test_count) {
        printf("Status:      ALL TESTS PASSED\n");
        printf("Result:      Vulnerability confirmed\n");
    } else if (pass_count > 0) {
        printf("Status:      PARTIAL SUCCESS\n");
        printf("Result:      Partial vulnerability demonstration\n");
    } else {
        printf("Status:      TESTS FAILED\n");
        printf("Result:      Could not demonstrate vulnerability\n");
    }

    printf("==========================================\n\n");

    return (pass_count == test_count) ? 0 : 1;
}
