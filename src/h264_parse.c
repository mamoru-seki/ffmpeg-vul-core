/*
 * FFmpeg h.264 Parser - Slice Counter Vulnerability Analysis
 *
 * This file demonstrates the vulnerable code path in h.264 slice parsing.
 * For demonstration purposes only - minimal reproduction of vulnerable pattern.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Slice information structure */
typedef struct {
    uint32_t slice_id;
    uint32_t start_pos;
    uint32_t size;
    uint8_t type;
} SliceInfo;

#define MAX_SLICES 1024
#define SLICE_ENTRY_SIZE sizeof(SliceInfo)

/*
 * VULNERABLE FUNCTION
 *
 * This function demonstrates the vulnerability:
 * - slice_count comes from untrusted input (bitstream)
 * - No validation before buffer allocation
 * - Integer overflow possible in size calculation
 */
int parse_slices_vulnerable(
    uint8_t *bitstream,
    uint32_t bitstream_len,
    SliceInfo **out_slices,
    uint32_t *out_slice_count
) {
    uint32_t slice_count;
    uint32_t buffer_size;
    SliceInfo *slice_buffer;
    uint32_t i;
    uint32_t pos = 0;

    if (!bitstream || !out_slices || !out_slice_count) {
        return -1;
    }

    /* VULNERABLE: Read slice count directly from bitstream */
    if (pos + 4 > bitstream_len) {
        fprintf(stderr, "Bitstream too short for slice count\n");
        return -1;
    }

    /* Extract slice count (big-endian) */
    slice_count = (bitstream[pos] << 24) |
                  (bitstream[pos+1] << 16) |
                  (bitstream[pos+2] << 8) |
                  (bitstream[pos+3]);
    pos += 4;

    printf("[VULNERABLE] slice_count from bitstream: %u (0x%08x)\n",
           slice_count, slice_count);

    /* VULNERABLE: No validation on slice_count */
    /* Integer overflow possible: slice_count * SLICE_ENTRY_SIZE */
    buffer_size = slice_count * SLICE_ENTRY_SIZE;

    printf("[VULNERABLE] Calculated buffer_size: %u (0x%08x)\n",
           buffer_size, buffer_size);

    /* VULNERABLE: No overflow check */
    if (buffer_size == 0 || buffer_size < slice_count) {
        fprintf(stderr, "WARNING: Integer overflow detected in buffer size\n");
        /* Note: Vulnerable code would proceed anyway */
    }

    /* Allocate buffer - may be undersized due to integer overflow */
    slice_buffer = (SliceInfo *)malloc(buffer_size);
    if (!slice_buffer) {
        fprintf(stderr, "Failed to allocate slice buffer\n");
        return -1;
    }

    printf("[VULNERABLE] Allocated buffer at %p, size: %u bytes\n",
           (void *)slice_buffer, buffer_size);

    /* VULNERABLE: Write slice data without bounds checking */
    /* If buffer_size overflowed, this will write out-of-bounds */
    for (i = 0; i < slice_count && pos + 12 <= bitstream_len; i++) {
        SliceInfo *slice = &slice_buffer[i];  /* VULNERABLE: Array access */

        slice->slice_id = (bitstream[pos] << 24) |
                         (bitstream[pos+1] << 16) |
                         (bitstream[pos+2] << 8) |
                         (bitstream[pos+3]);
        pos += 4;

        slice->start_pos = (bitstream[pos] << 24) |
                          (bitstream[pos+1] << 16) |
                          (bitstream[pos+2] << 8) |
                          (bitstream[pos+3]);
        pos += 4;

        slice->size = (bitstream[pos] << 24) |
                     (bitstream[pos+1] << 16) |
                     (bitstream[pos+2] << 8) |
                     (bitstream[pos+3]);
        pos += 4;

        slice->type = bitstream[pos];
        pos += 1;

        printf("[VERBOSE] Slice %u: id=%u start=%u size=%u type=%u\n",
               i, slice->slice_id, slice->start_pos, slice->size, slice->type);

        /* If i * sizeof(SliceInfo) exceeds buffer_size, OOB write occurs */
        if ((i + 1) * SLICE_ENTRY_SIZE > buffer_size) {
            fprintf(stderr, "WARNING: Writing beyond allocated buffer!\n");
            fprintf(stderr, "  Allocated: %u bytes\n", buffer_size);
            fprintf(stderr, "  Writing to offset: %u bytes\n", (i + 1) * SLICE_ENTRY_SIZE);
            /* Vulnerable code continues anyway, causing heap corruption */
        }
    }

    if (i < slice_count) {
        fprintf(stderr, "WARNING: Incomplete slice data in bitstream\n");
    }

    *out_slices = slice_buffer;
    *out_slice_count = i;

    return 0;
}

/*
 * PATCHED FUNCTION
 *
 * Includes proper validation and overflow checks
 */
int parse_slices_patched(
    uint8_t *bitstream,
    uint32_t bitstream_len,
    SliceInfo **out_slices,
    uint32_t *out_slice_count
) {
    uint32_t slice_count;
    size_t buffer_size;
    SliceInfo *slice_buffer;
    uint32_t i;
    uint32_t pos = 0;

    if (!bitstream || !out_slices || !out_slice_count) {
        return -1;
    }

    /* Read slice count */
    if (pos + 4 > bitstream_len) {
        fprintf(stderr, "Bitstream too short for slice count\n");
        return -1;
    }

    slice_count = (bitstream[pos] << 24) |
                  (bitstream[pos+1] << 16) |
                  (bitstream[pos+2] << 8) |
                  (bitstream[pos+3]);
    pos += 4;

    printf("[PATCHED] slice_count from bitstream: %u (0x%08x)\n",
           slice_count, slice_count);

    /* PATCHED: Validate slice count against maximum */
    if (slice_count > MAX_SLICES) {
        fprintf(stderr, "ERROR: slice_count exceeds maximum (%u > %u)\n",
                slice_count, MAX_SLICES);
        return -1;
    }

    printf("[PATCHED] slice_count validation PASSED\n");

    /* PATCHED: Safe multiplication with overflow check */
    /* Using size_t and checking for overflow */
    if (slice_count > SIZE_MAX / SLICE_ENTRY_SIZE) {
        fprintf(stderr, "ERROR: Buffer size would overflow\n");
        return -1;
    }

    buffer_size = (size_t)slice_count * SLICE_ENTRY_SIZE;

    printf("[PATCHED] Calculated buffer_size: %zu bytes (validated)\n", buffer_size);

    /* Allocate buffer */
    slice_buffer = (SliceInfo *)malloc(buffer_size);
    if (!slice_buffer) {
        fprintf(stderr, "Failed to allocate slice buffer\n");
        return -1;
    }

    printf("[PATCHED] Allocated buffer at %p, size: %zu bytes\n",
           (void *)slice_buffer, buffer_size);

    /* Parse slice data with proper bounds checking */
    for (i = 0; i < slice_count && pos + 12 <= bitstream_len; i++) {
        SliceInfo *slice = &slice_buffer[i];

        /* PATCHED: Verify we're not writing beyond buffer */
        if ((i + 1) * SLICE_ENTRY_SIZE > buffer_size) {
            fprintf(stderr, "ERROR: Buffer bounds exceeded at slice %u\n", i);
            free(slice_buffer);
            return -1;
        }

        slice->slice_id = (bitstream[pos] << 24) |
                         (bitstream[pos+1] << 16) |
                         (bitstream[pos+2] << 8) |
                         (bitstream[pos+3]);
        pos += 4;

        slice->start_pos = (bitstream[pos] << 24) |
                          (bitstream[pos+1] << 16) |
                          (bitstream[pos+2] << 8) |
                          (bitstream[pos+3]);
        pos += 4;

        slice->size = (bitstream[pos] << 24) |
                     (bitstream[pos+1] << 16) |
                     (bitstream[pos+2] << 8) |
                     (bitstream[pos+3]);
        pos += 4;

        slice->type = bitstream[pos];
        pos += 1;

        printf("[VERBOSE] Slice %u: id=%u start=%u size=%u type=%u\n",
               i, slice->slice_id, slice->start_pos, slice->size, slice->type);
    }

    if (i < slice_count) {
        fprintf(stderr, "WARNING: Incomplete slice data in bitstream\n");
    }

    *out_slices = slice_buffer;
    *out_slice_count = i;

    return 0;
}

/*
 * Cleanup function
 */
void free_slices(SliceInfo *slices) {
    if (slices) {
        free(slices);
    }
}
