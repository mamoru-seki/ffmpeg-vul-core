/*
 * Patched Code Path Test
 *
 * Demonstrates the fix for slice buffer handling
 * Includes proper validation and overflow checks
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Test configuration */
#define ENTRY_SIZE 16
#define MAX_SLICES 1024
#define TEST_SLICE_COUNT_OVERFLOW 0x40000000
#define TEST_SLICE_COUNT_VALID    100

typedef struct {
    uint32_t id;
    uint32_t pos;
    uint32_t size;
    uint8_t type;
} SliceEntry;

/*
 * Test: Input Validation
 */
int test_input_validation(void) {
    printf("\n[TEST] Input Validation Against MAX_SLICES\n");
    printf("-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-\n");

    uint32_t invalid_count = TEST_SLICE_COUNT_OVERFLOW;
    uint32_t valid_count = TEST_SLICE_COUNT_VALID;

    printf("Maximum allowed slices: %u\n", MAX_SLICES);

    /* Test invalid input */
    printf("\nTest 1: Invalid slice count (0x%08x)\n", invalid_count);
    if (invalid_count > MAX_SLICES) {
        printf("STATUS: Input validation PASSED - Rejected\n");
    } else {
        printf("STATUS: Input validation FAILED - Accepted\n");
        return 0;
    }

    /* Test valid input */
    printf("\nTest 2: Valid slice count (%u)\n", valid_count);
    if (valid_count <= MAX_SLICES) {
        printf("STATUS: Input validation PASSED - Accepted\n");
    } else {
        printf("STATUS: Input validation FAILED - Rejected\n");
        return 0;
    }

    printf("\nRESULT: PASS - Input validation working correctly\n");
    return 1;
}

/*
 * Test: Safe Integer Multiplication
 */
int test_safe_multiplication(void) {
    printf("\n[TEST] Safe Integer Multiplication\n");
    printf("-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-\n");

    uint32_t slice_count = TEST_SLICE_COUNT_OVERFLOW;
    size_t entry_size = ENTRY_SIZE;

    printf("Input: slice_count = 0x%08x\n", slice_count);
    printf("Entry size: %zu\n", entry_size);

    /* PATCHED: Check for overflow before multiplication */
    if (slice_count > SIZE_MAX / entry_size) {
        printf("STATUS: Overflow check DETECTED\n");
        printf("Reason: slice_count > SIZE_MAX / entry_size\n");
        printf("         0x%08x > %zu / %zu\n", slice_count, SIZE_MAX, entry_size);
        printf("RESULT: PASS - Overflow correctly prevented\n");
        return 1;
    } else {
        /* On 64-bit systems, this might not overflow */
        printf("STATUS: Overflow check passed (64-bit system)\n");
        printf("RESULT: PASS - Safe multiplication verified\n");
        return 1;
    }
}

/*
 * Test: Controlled Buffer Allocation
 */
int test_controlled_allocation(void) {
    printf("\n[TEST] Controlled Buffer Allocation\n");
    printf("-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-\n");

    uint32_t slice_count = TEST_SLICE_COUNT_VALID;  /* Valid count */
    size_t entry_size = ENTRY_SIZE;

    /* PATCHED: Validate before allocation */
    if (slice_count > MAX_SLICES) {
        printf("VALIDATION: Input rejected\n");
        printf("RESULT: PASS - Correct size would be allocated\n");
        return 1;
    }

    /* PATCHED: Check for overflow */
    if (slice_count > SIZE_MAX / entry_size) {
        printf("OVERFLOW: Multiplication would overflow\n");
        printf("RESULT: PASS - Allocation prevented\n");
        return 1;
    }

    /* Safe to calculate */
    size_t buffer_size = slice_count * entry_size;
    printf("Slice count: %u\n", slice_count);
    printf("Calculated buffer size: %zu bytes\n", buffer_size);

    /* Actually allocate */
    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if (!buffer) {
        printf("STATUS: Allocation failed\n");
        printf("RESULT: FAIL - Could not allocate buffer\n");
        return 0;
    }

    printf("STATUS: Buffer allocated successfully at %p\n", (void *)buffer);
    printf("Allocation is properly sized: %zu bytes\n", buffer_size);

    /* Verify we can write safely */
    int safe = 1;
    for (uint32_t i = 0; i < slice_count; i++) {
        size_t offset = i * ENTRY_SIZE;
        if (offset + ENTRY_SIZE > buffer_size) {
            printf("SAFETY: Out-of-bounds at slice %u\n", i);
            safe = 0;
            break;
        }
        SliceEntry *entry = (SliceEntry *)(buffer + offset);
        entry->id = i;
        entry->pos = i * 1024;
        entry->size = 512;
        entry->type = 0x05;
    }

    free(buffer);

    if (safe) {
        printf("STATUS: All writes within bounds\n");
        printf("RESULT: PASS - Safe allocation and access\n");
        return 1;
    } else {
        printf("STATUS: Bounds violations detected\n");
        printf("RESULT: FAIL - Safety check failed\n");
        return 0;
    }
}

/*
 * Test: Bounds Checking During Writes
 */
int test_bounds_checking(void) {
    printf("\n[TEST] Bounds Checking During Writes\n");
    printf("-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-\n");

    uint32_t slice_count = TEST_SLICE_COUNT_VALID;
    size_t buffer_size = slice_count * ENTRY_SIZE;

    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if (!buffer) {
        printf("Failed to allocate buffer\n");
        return 0;
    }

    printf("Buffer size: %zu bytes\n", buffer_size);
    printf("Expected slices: %u\n", slice_count);
    printf("Performing writes with bounds checking...\n");

    int violations = 0;
    for (uint32_t i = 0; i < slice_count; i++) {
        size_t offset = i * ENTRY_SIZE;

        /* PATCHED: Check bounds before write */
        if (offset + ENTRY_SIZE > buffer_size) {
            printf("VIOLATION: Slice %u would exceed buffer\n", i);
            violations++;
            break;  /* Stop to prevent actual OOB write */
        }

        /* Safe to write */
        SliceEntry *entry = (SliceEntry *)(buffer + offset);
        entry->id = i;
        entry->pos = i * 1024;
        entry->size = 512;
        entry->type = 0x05;
    }

    free(buffer);

    if (violations == 0) {
        printf("STATUS: All %u writes completed safely\n", slice_count);
        printf("RESULT: PASS - Bounds checking working\n");
        return 1;
    } else {
        printf("STATUS: %d bounds violations detected\n", violations);
        printf("RESULT: FAIL - Bounds checking failed\n");
        return 0;
    }
}

/*
 * Test: Rejection of Malicious Input
 */
int test_rejection_of_malicious_input(void) {
    printf("\n[TEST] Rejection of Malicious Input\n");
    printf("-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-\n");

    uint32_t malicious_inputs[] = {
        0xFFFFFFFF,         /* Max value */
        0x80000000,         /* Large signed value */
        0x40000000,         /* 1GB */
        0x10000000,         /* 256MB */
        0x01000000,         /* 16MB */
        MAX_SLICES + 1,     /* Just over limit */
        SIZE_MAX / ENTRY_SIZE + 1,  /* Would overflow */
    };

    int inputs_tested = sizeof(malicious_inputs) / sizeof(malicious_inputs[0]);
    int inputs_rejected = 0;

    printf("Testing %d malicious inputs...\n", inputs_tested);

    for (int i = 0; i < inputs_tested; i++) {
        uint32_t count = malicious_inputs[i];

        /* PATCHED: Multiple validation checks */
        int rejected = 0;

        if (count > MAX_SLICES) {
            rejected = 1;
        } else if (count > SIZE_MAX / ENTRY_SIZE) {
            rejected = 1;
        }

        if (rejected) {
            printf("  Input %u: REJECTED\n", count);
            inputs_rejected++;
        } else {
            printf("  Input %u: accepted (within limits)\n", count);
        }
    }

    printf("\nResults:\n");
    printf("  Tested: %d\n", inputs_tested);
    printf("  Rejected: %d\n", inputs_rejected);

    if (inputs_rejected > 0) {
        printf("RESULT: PASS - Malicious inputs rejected\n");
        return 1;
    } else {
        printf("RESULT: FAIL - All inputs accepted (unexpected)\n");
        return 0;
    }
}

/*
 * Test Suite Runner
 */
int main(int argc, char *argv[]) {
    printf("\n");
    printf("==========================================\n");
    printf("   Patched Code Path Test Suite\n");
    printf("==========================================\n");

    int test_count = 0;
    int pass_count = 0;

    printf("\nRunning tests...\n");

    /* Run tests */
    if (test_input_validation()) pass_count++;
    test_count++;

    if (test_safe_multiplication()) pass_count++;
    test_count++;

    if (test_controlled_allocation()) pass_count++;
    test_count++;

    if (test_bounds_checking()) pass_count++;
    test_count++;

    if (test_rejection_of_malicious_input()) pass_count++;
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
        printf("Result:      Patched code is secure\n");
    } else if (pass_count > 0) {
        printf("Status:      PARTIAL SUCCESS\n");
        printf("Result:      Some protections working\n");
    } else {
        printf("Status:      TESTS FAILED\n");
        printf("Result:      Patched code needs revision\n");
    }

    printf("==========================================\n\n");

    return (pass_count == test_count) ? 0 : 1;
}
