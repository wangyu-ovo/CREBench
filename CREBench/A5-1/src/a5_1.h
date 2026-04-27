#ifndef A5_1_H
#define A5_1_H

#include <stddef.h>
#include <stdint.h>

#define A5_1_KEY_BYTES 8
#define A5_1_FRAME_BYTES 4
#define A5_1_BURST_BITS 114
#define A5_1_BURST_BYTES 15
#define A5_1_FRAME_STREAM_BYTES (A5_1_BURST_BYTES * 2)

void a5_1_generate_bursts(
    const uint8_t key[A5_1_KEY_BYTES],
    uint32_t frame_number,
    uint8_t dl_bits[A5_1_BURST_BITS],
    uint8_t ul_bits[A5_1_BURST_BITS]
);

void a5_1_frame_stream(
    const uint8_t key[A5_1_KEY_BYTES],
    uint32_t frame_number,
    uint8_t stream[A5_1_FRAME_STREAM_BYTES]
);

void a5_1_crypt(
    const uint8_t key[A5_1_KEY_BYTES],
    uint32_t frame_number,
    const uint8_t *input,
    uint8_t *output,
    size_t len
);

#endif /* A5_1_H */

