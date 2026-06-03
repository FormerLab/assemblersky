# Changelog

All notable changes to Assemblersky are documented here.

---

## [0.7] — 2026-06-03

### Security

- **`cbor_scan.asm` — integer overflow / infinite loop (CVE-class: DoS)**
  `decode_head` now clamps byte/text lengths (major types 2, 3) to the
  remaining buffer size. A crafted u64 length of `0xffffffffffffffff` previously
  caused callers to walk far past the end of the buffer. Reported with PoC.

- **`cbor_scan.asm` — array/map count overflow → infinite loop**
  Array and map counts (major types 4, 5) are now capped at 65535. A crafted
  u64 count previously caused `skip_item` to loop `2^64 - 1` times. Same root
  cause as above; separate clamp path since counts are not byte lengths.

- **`cbor_scan.asm` — stack exhaustion via deeply nested structures**
  `skip_item` now tracks recursion depth and fails if depth exceeds 64.
  Crafted deeply nested CBOR arrays/maps/tags previously caused stack
  exhaustion. Reported with PoC (`stack_overflow.bin`).

- **`cbor_scan.asm` — OOB read via crafted text length**
  Variant of the length overflow: a crafted map with a text key claiming
  a huge length caused an out-of-bounds read. Fixed by the same byte/text
  length clamp. Reported with PoC (`oob_read.bin`).

- **`post_extract.asm` — `read_len_rec` missing u64 branch**
  `read_len_rec` previously fell through to `.fail` on CBOR additional-info
  value 27 (u64 length). Added u64 decoding with the same buffer clamp as
  `cbor_scan.asm`.

- **`post_extract.asm` — `skip_item_rec` stack exhaustion**
  `skip_item_rec` now uses `r10` as a depth counter (initialised to 0 at
  top-level call sites) and fails if depth exceeds 64. Defensive fix;
  no PoC provided for this code path specifically.

### Notes

The three provided PoC inputs (`infinite_loop.bin`, `stack_overflow.bin`,
`oob_read.bin`) all return exit code 1 immediately with the patched build.
The fixture test (`tests/fixtures/relay_commit_frame.bin`) continues to pass.

---

## [0.6] — 2026-03-26

### Added

- Initial public release on GitHub and Tangled
- Full four-stage AT Protocol firehose decode pipeline in x86-64 NASM assembly:
  - `asb_decode_envelope` — CBOR envelope parser (`cbor_scan.asm`)
  - `asb_find_create_post_op` — ops array walker (`post_extract.asm`)
  - `asb_car_find_block` — CARv1 block scanner (`car_scan.asm`)
  - `asb_extract_post_record` — DAG-CBOR record extractor (`post_extract.asm`)
- Rust harness wrapping assembly via C ABI, emitting normalized NDJSON
- Synthetic relay commit fixture + `make test`
- Integration with Fortransky as preferred `relay-raw` decoder

### Fixed (bring-up, from development session)

- `cbor_scan.asm`: `rsi` (end pointer) not preserved across helper calls —
  reloaded from callee-save `r12` before every `call`
- `cbor_scan.asm`: `match_key` clobbered `rbx` (key pointer) via `bl` —
  added `push`/`pop rbx`
- `post_extract.asm`: `asb_find_create_post_op` returned next pointer via
  `mov eax, r12d` — 32-bit truncation of 64-bit pointer on ASLR systems;
  changed to `mov rax, r12`
- `post_extract.asm`: path prefix comparison used `match_bytes` with full
  path length instead of prefix length — added `mov rcx, POST_PREFIX_LEN`
- `post_extract.asm`: `asb_mem_eq` call sites passed key length in wrong
  register — fixed argument setup
- `car_scan.asm`: `_guess_cid_len` did not preserve `rsi` across
  `_decode_varint` calls — added `push`/`pop r13` to save section end
- `car_scan.asm`: `asb_car_find_block` output pointer arguments `r8`/`r9`
  clobbered by `_decode_varint` — saved to stack on entry
