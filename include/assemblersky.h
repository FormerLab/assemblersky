#ifndef ASSEMBLERSKY_H
#define ASSEMBLERSKY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t seq;
    const uint8_t *repo_ptr;
    size_t repo_len;
    const uint8_t *rev_ptr;
    size_t rev_len;
    const uint8_t *ops_ptr;
    size_t ops_len;
    const uint8_t *blocks_ptr;
    size_t blocks_len;
    int is_commit;
} asb_envelope_t;

typedef struct {
    const uint8_t *collection_ptr;
    size_t collection_len;
    const uint8_t *rkey_ptr;
    size_t rkey_len;
    const uint8_t *cid_ptr;
    size_t cid_len;
    const uint8_t *record_cid_ptr;
    size_t record_cid_len;
    int is_create_post;
} asb_post_op_t;

typedef struct {
    const uint8_t *type_ptr;
    size_t type_len;
    const uint8_t *text_ptr;
    size_t text_len;
    const uint8_t *created_at_ptr;
    size_t created_at_len;
    int ok;
} asb_post_record_t;

int asb_decode_envelope(const uint8_t *buf, size_t len, asb_envelope_t *out);
int asb_find_create_post_op(const uint8_t *ops_buf, size_t ops_len, asb_post_op_t *out);
int asb_car_find_block(const uint8_t *car_buf, size_t car_len,
                       const uint8_t *target_cid, size_t target_cid_len,
                       const uint8_t **block_ptr, size_t *block_len);
int asb_extract_post_record(const uint8_t *block_buf, size_t block_len, asb_post_record_t *out);

#ifdef __cplusplus
}
#endif

#endif
