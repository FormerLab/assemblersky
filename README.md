# Assemblersky

An x86-64 assembly decoder engine for Bluesky / AT Protocol firehose frames.
Part of the Fortransky ecosystem — an alternate `relay-raw` decoder path.

> Raw binary frames from the AT Protocol relay, decoded in x86-64 assembly.
> No runtime. No abstractions. Just registers and the protocol.

---

## Architecture

```
Raw relay frame (binary CBOR over WebSocket)
  → asb_decode_envelope()     CBOR envelope → seq, repo, rev, ops slice, blocks slice
  → asb_find_create_post_op() ops array → collection, rkey, CID
  → asb_car_find_block()      CARv1 → record block bytes
  → asb_extract_post_record() DAG-CBOR → $type, text, createdAt
  → normalized NDJSON
```

All four stages are implemented in x86-64 NASM assembly (SysV ABI).
A thin Rust harness wraps the assembly via a C ABI, calls all four stages
in sequence, and emits normalized NDJSON — the same schema as the Rust
`firehose_bridge_cli` in Fortransky, so Fortransky's relay helper accepts
either decoder transparently.

### Why assembly

The AT Protocol relay speaks `com.atproto.sync.subscribeRepos` — binary
WebSocket frames containing concatenated CBOR items. Each frame carries a
header map, a body map, a CARv1 block store, and DAG-CBOR encoded records.
Three nested binary formats before you see a post.

Assemblersky decodes all of it with no allocator, no garbage collector, and
no language runtime. Every instruction between the raw frame bytes and the
output JSON is explicit and auditable. The decode pipeline is a direct
translation of the AT Protocol wire format into register operations.

---

## SysV ABI discipline

The assembly is strict about the x86-64 SysV calling convention:

- Callee-save registers (`rbx`, `r12`–`r15`, `rbp`) are pushed on entry
  and popped on exit for every function.
- Caller-save registers (`rsi`, `rdi`, `rcx`, `rdx`, `r8`, `r9`, `r10`,
  `r11`) are reloaded from callee-save registers before every call that
  needs them — they cannot be assumed to survive across a `call`.
- `rsi` (end pointer) in particular must be reloaded before every helper
  call since nearly all helpers use it as a bounds limit.
- Output pointer arguments passed in `r8`/`r9` are saved to the stack
  immediately on entry, as `_decode_varint` clobbers both.

---

## Build dependencies

- NASM (`sudo apt install nasm`)
- Rust toolchain (`rustup` or distro package)
- C compiler (`gcc` or `clang`, pulled in via the `cc` crate)

## Build

```bash
make
```

Or manually:

```bash
cd rust-harness
ASB_ROOT=$(pwd)/.. cargo build --release
```

## Test against fixture

```bash
make test
```

Expected output:

```json
{
    "kind": "commit",
    "op": "create",
    "collection": "app.bsky.feed.post",
    "seq": 26653242501,
    "repo": "did:plc:fortranskyfixture000000000000",
    "rev": "3lmfixture-rev",
    "rkey": "3lmfixturepost",
    "record": {
        "$type": "app.bsky.feed.post",
        "text": "Synthetic raw relay commit fixture: hello from Fortransky.",
        "created_at": "2026-03-19T00:00:00.000Z"
    }
}
```

---

## Integration with Fortransky

Copy the built binary into the Fortransky repo:

```bash
mkdir -p ../fortransky/bridge/assemblersky/bin
cp rust-harness/target/release/assemblersky-harness \
   ../fortransky/bridge/assemblersky/bin/assemblersky_cli
```

Fortransky's `relay_raw_tail.py` auto-detects `assemblersky_cli` and prefers
it over the Rust firehose bridge decoder. Detection order:

1. `FORTRANSKY_RELAY_DECODER` env var
2. `FORTRANSKY_ASSEMBLERSKY_DECODER` env var
3. `bridge/assemblersky/bin/assemblersky_cli` (bundled)
4. `assemblersky_cli` on `PATH`
5. Rust `firehose_bridge_cli` (fallback)

To verify which decoder is active, check `~/.fortransky/relay_raw_tail.out`
after a stream refresh — events decoded by Assemblersky carry
`"source": "relay-raw-native"` from the Rust harness output.

---

## Scope

- `#commit` frames only
- `create` ops only
- `app.bsky.feed.post` collection only
- Definite-length CBOR subset (indefinite-length items fail gracefully)
- Linux x86-64 only (SysV ABI)

The CID in commit ops is captured as raw bytes — no semantic CID decode.
The CAR block scanner uses a heuristic varint walk to determine CID length
rather than a full multicodec parse.

---

## Files

```
asm/
  cbor_scan.asm        asb_decode_envelope — CBOR envelope + body map parser
  car_scan.asm         asb_car_find_block  — CARv1 varint scanner + CID match
  post_extract.asm     asb_find_create_post_op + asb_extract_post_record
  util.asm             asb_mem_eq          — bounded memory compare

include/
  assemblersky.h       C ABI header — struct definitions + function prototypes

cshim/
  assemblersky_exports.c   C-visible glue declarations (no logic)

rust-harness/
  src/main.rs          CLI entry point — calls all 4 stages, emits NDJSON
  src/ffi.rs           Rust FFI bindings to the assembly functions
  src/normalize.rs     NormalizedEvent + NormalizedRecord output structs
  build.rs             Compiles NASM sources + C shim via cc crate
  Cargo.toml

tests/
  fixtures/relay_commit_frame.bin    Synthetic raw #commit relay frame
  expected/relay_commit_frame.json   Expected normalized output shape
```

---

## Part of the Former Lab ecosystem

Assemblersky is part of [Fortransky](https://github.com/FormerLab/fortransky) —
a Bluesky client written in Fortran. The decode pipeline:

```
Fortran TUI
  └─ Python relay helper
       └─ assemblersky_cli  (this project)
            └─ x86-64 assembly  →  Rust harness  →  NDJSON
```

Former Lab: [formerlab.bsky.social](https://bsky.app/profile/formerlab.bsky.social)