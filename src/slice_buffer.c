/*
 * Slice Buffer Counter Implementation
 *
 * Demonstrates the vulnerable slice buffer counter management
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t size;
    uint32_t slice_count;
} SliceBuffer;

/*
 * VULNERABLE: Create slice buffer
 *
 * Integer overflow in capacity calculation
 */
SliceBuffer *slice_buffer_create_vulnerable(uint32_t slice_count) {
    SliceBuffer *buf = (SliceBuffer *)malloc(sizeof(SliceBuffer));
    if (!buf) {
        return NULL;
    }

    size_t entry_size = 16;  /* sizeof(SliceInfo) */

    /* VULNERABLE: No overflow check */
    size_t capacity = slice_count * entry_size;

    printf("[VULN] Creating slice buffer for %u slices\n", slice_count);
    printf("[VULN] Requested capacity: %zu (0x%zx)\n", capacity, capacity);

    /* VULNERABLE: Allocate with potentially overflowed size */
    buf->data = (uint8_t *)malloc(capacity);
    if (!buf->data) {
        fprintf(stderr, "Failed to allocate %zu bytes\n", capacity);
        free(buf);
        return NULL;
    }

    buf->capacity = capacity;
    buf->size = 0;
    buf->slice_count = slice_count;

    printf("[VULN] Allocated %zu bytes at %p\n", capacity, (void *)buf->data);
    printf("[VULN] Actual slice count: %u\n", buf->slice_count);

    return buf;
}

/*
 * PATCHED: Create slice buffer with validation
 */
SliceBuffer *slice_buffer_create_patched(uint32_t slice_count) {
    SliceBuffer *buf = (SliceBuffer *)malloc(sizeof(SliceBuffer));
    if (!buf) {
        return NULL;
    }

    size_t entry_size = 16;  /* sizeof(SliceInfo) */

    /* PATCHED: Validate slice count */
    #define MAX_SLICES 1024
    if (slice_count > MAX_SLICES) {
        fprintf(stderr, "ERROR: slice_count (%u) exceeds MAX_SLICES (%u)\n",
                slice_count, MAX_SLICES);
        free(buf);
        return NULL;
    }

    /* PATCHED: Safe multiplication with overflow check */
    size_t capacity;
    if (slice_count > SIZE_MAX / entry_size) {
        fprintf(stderr, "ERROR: Capacity calculation would overflow\n");
        free(buf);
        return NULL;
    }
    capacity = slice_count * entry_size;

    printf("[PATCHED] Creating slice buffer for %u slices\n", slice_count);
    printf("[PATCHED] Requested capacity: %zu (validated)\n", capacity);

    buf->data = (uint8_t *)malloc(capacity);
    if (!buf->data) {
        fprintf(stderr, "Failed to allocate %zu bytes\n", capacity);
        free(buf);
        return NULL;
    }

    buf->capacity = capacity;
    buf->size = 0;
    buf->slice_count = slice_count;

    printf("[PATCHED] Allocated %zu bytes at %p\n", capacity, (void *)buf->data);
    printf("[PATCHED] Actual slice count: %u\n", buf->slice_count);

    return buf;
}

/*
 * VULNERABLE: Write slice entry
 *
 * No bounds checking on array access
 */
int slice_buffer_write_vulnerable(SliceBuffer *buf, uint32_t index,
                                  const uint8_t *data, size_t data_len) {
    if (!buf || !data) {
        return -1;
    }

    /* VULNERABLE: No bounds check on index */
    size_t offset = index * 16;  /* entry_size */

    printf("[VULN] Writing slice %u at offset %zu\n", index, offset);

    /* VULNERABLE: Write without verifying offset is within capacity */
    if (offset + data_len > buf->capacity) {
        fprintf(stderr, "WARNING: Writing beyond allocated buffer!\n");
        fprintf(stderr, "  Buffer capacity: %zu\n", buf->capacity);
        fprintf(stderr, "  Write offset: %zu\n", offset);
        fprintf(stderr, "  Write size: %zu\n", data_len);
        fprintf(stderr, "  Total: %zu\n", offset + data_len);
        /* Vulnerable code continues - OOB write */
    }

    memcpy(buf->data + offset, data, data_len);  /* VULNERABLE: OOB access */

    if (offset + data_len > buf->size) {
        buf->size = offset + data_len;
    }

    return 0;
}

/*
 * PATCHED: Write slice entry with validation
 */
int slice_buffer_write_patched(SliceBuffer *buf, uint32_t index,
                               const uint8_t *data, size_t data_len) {
    if (!buf || !data) {
        return -1;
    }

    /* PATCHED: Validate index is within slice_count */
    if (index >= buf->slice_count) {
        fprintf(stderr, "ERROR: Index %u exceeds slice_count %u\n",
                index, buf->slice_count);
        return -1;
    }

    size_t offset = index * 16;  /* entry_size */

    printf("[PATCHED] Writing slice %u at offset %zu\n", index, offset);

    /* PATCHED: Verify write is within capacity */
    if (offset + data_len > buf->capacity) {
        fprintf(stderr, "ERROR: Write would exceed buffer capacity\n");
        fprintf(stderr, "  Buffer capacity: %zu\n", buf->capacity);
        fprintf(stderr, "  Required: %zu\n", offset + data_len);
        return -1;
    }

    memcpy(buf->data + offset, data, data_len);

    if (offset + data_len > buf->size) {
        buf->size = offset + data_len;
    }

    printf("[PATCHED] Successfully wrote %zu bytes\n", data_len);
    return 0;
}

/*
 * Read slice entry
 */
int slice_buffer_read(SliceBuffer *buf, uint32_t index,
                     uint8_t *out_data, size_t data_len) {
    if (!buf || !out_data) {
        return -1;
    }

    size_t offset = index * 16;

    if (offset + data_len > buf->size) {
        fprintf(stderr, "ERROR: Read would exceed buffer size\n");
        return -1;
    }

    memcpy(out_data, buf->data + offset, data_len);
    return 0;
}

/*
 * Destroy slice buffer
 */
void slice_buffer_destroy(SliceBuffer *buf) {
    if (buf) {
        if (buf->data) {
            free(buf->data);
        }
        free(buf);
    }
}

/*
 * Get buffer statistics
 */
void slice_buffer_stats(SliceBuffer *buf) {
    if (!buf) {
        return;
    }

    printf("\n=== Slice Buffer Statistics ===\n");
    printf("Slice count:      %u\n", buf->slice_count);
    printf("Buffer capacity:  %zu bytes\n", buf->capacity);
    printf("Buffer size used: %zu bytes\n", buf->size);
    printf("Expected size:    %zu bytes\n", (size_t)buf->slice_count * 16);

    if (buf->size <= buf->capacity) {
        printf("Status:           SAFE\n");
    } else {
        printf("Status:           OVERFLOW (should not occur)\n");
    }
    printf("==============================\n\n");
}
