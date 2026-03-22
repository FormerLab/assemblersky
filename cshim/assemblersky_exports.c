#include "../include/assemblersky.h"

/*
 * Thin C-visible declarations for the assembly exports.
 * This file intentionally contains no logic; it exists so Rust/C build systems
 * have a stable translation unit and visible prototypes.
 */

int asb_decode_envelope(const uint8_t *buf, size_t len, asb_envelope_t *out);
int asb_find_create_post_op(const uint8_t *ops_buf, size_t ops_len, asb_post_op_t *out);
int asb_car_find_block(const uint8_t *car_buf, size_t car_len,
                       const uint8_t *target_cid, size_t target_cid_len,
                       const uint8_t **block_ptr, size_t *block_len);
int asb_extract_post_record(const uint8_t *block_buf, size_t block_len, asb_post_record_t *out);
