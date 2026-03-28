# Assemblersky

x86-64 assembly decoding the Bluesky firehose

CBOR → CAR → DAG-CBOR → post text. No runtime. No abstractions. Just registers
and the protocol.

Part of the [Fortransky](https://github.com/FormerLab/fortransky) ecosystem —
an AT Protocol client written in Fortran.

---

## What it does

The AT Protocol relay (`com.atproto.sync.subscribeRepos`) speaks binary
WebSocket frames. Each frame contains three nested binary formats before you
reach a post:

```
Raw WebSocket frame
  └─ CBOR envelope     {op, t, seq, repo, rev, ops, blocks}
       └─ CARv1 block store
            └─ DAG-CBOR record   {$type, text, createdAt, ...}
```

Assemblersky decodes all of it in x86-64 NASM assembly — four functions,
four stages, no allocator, no garbage collector, no language runtime:

```
asb_decode_envelope()     CBOR envelope → seq, repo, rev, ops slice, blocks
asb_find_create_post_op() ops array → collection, rkey, CID
asb_car_find_block()      CARv1 → record block bytes
asb_extract_post_record() DAG-CBOR → $type, text, createdAt
```

A thin Rust harness wraps the assembly via a C ABI and emits normalized NDJSON —
the same schema as Fortransky's Rust firehose bridge, so both decoders are
interchangeable.

---

## Architecture

```
assemblersky-harness (Rust CLI)
  └─ ffi.rs           Rust FFI bindings → C ABI
       └─ assemblersky_exports.c   C glue
            └─ cbor_scan.asm       asb_decode_envelope
            └─ car_scan.asm        asb_car_find_block
            └─ post_extract.asm    asb_find_create_post_op + asb_extract_post_record
            └─ util.asm            asb_mem_eq
```

---

## SysV ABI discipline

The assembly is strict about the x86-64 SysV calling convention. Getting this
wrong is the main class of bug in assembly code that calls other assembly:

- **Callee-save registers** (`rbx`, `r12`–`r15`, `rbp`) — pushed on entry,
  popped on exit for every function
- **Caller-save registers** (`rsi`, `rdi`, `rcx`, `rdx`, `r8`, `r9`) —
  reloaded from callee-save registers before every call that needs them;
  cannot be assumed to survive across a `call`
- **`rsi` (end pointer)** — must be reloaded before every helper call since
  nearly all helpers use it as a bounds limit
- **Output pointer arguments** (`r8`, `r9`)** — saved to the stack on entry
  since `_decode_varint` and similar helpers clobber both

The bring-up debugging session that fixed these is documented in the git history.

---

## Build dependencies

- NASM (`sudo apt install nasm` / `sudo pacman -S nasm`)
- Rust toolchain >= 1.78 (`rustup` or distro package)
- C compiler (`gcc` or `clang`, via the `cc` crate)

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

## Integrated with Fortransky already, but if you ever accidently delete it  :) 

```bash
mkdir -p ../fortransky/bridge/assemblersky/bin
cp rust-harness/target/release/assemblersky-harness \
   ../fortransky/bridge/assemblersky/bin/assemblersky_cli
```

Fortransky's `relay_raw_tail.py` auto-detects `assemblersky_cli` and prefers
it over the Rust firehose bridge. Detection order:

1. `FORTRANSKY_RELAY_DECODER` env var
2. `FORTRANSKY_ASSEMBLERSKY_DECODER` env var
3. `bridge/assemblersky/bin/assemblersky_cli` (bundled)
4. `assemblersky_cli` on `PATH`
5. Rust `firehose_bridge_cli` fallback

Check detection: `./scripts/check_assemblersky.sh`

---

## Scope

- `#commit` frames only
- `create` ops only
- `app.bsky.feed.post` collection only
- Definite-length CBOR subset (indefinite-length items fail gracefully)
- Linux x86-64 only (SysV ABI)

The CID in commit ops is captured as raw bytes — no semantic CID decode.
The CAR block scanner uses a heuristic varint walk to determine CID length.

---

## Files

```
asm/
  cbor_scan.asm      asb_decode_envelope — CBOR envelope + body map parser
  car_scan.asm       asb_car_find_block  — CARv1 varint scanner + CID match
  post_extract.asm   asb_find_create_post_op + asb_extract_post_record
  util.asm           asb_mem_eq — bounded memory compare

include/
  assemblersky.h     C ABI header — struct definitions + function prototypes

cshim/
  assemblersky_exports.c   C-visible glue (no logic)

rust-harness/
  src/main.rs        CLI entry point — calls all 4 stages, emits NDJSON
  src/ffi.rs         Rust FFI bindings
  src/normalize.rs   NormalizedEvent + NormalizedRecord output structs
  build.rs           Compiles NASM + C shim via cc crate
  Cargo.toml

tests/
  fixtures/relay_commit_frame.bin    Synthetic raw #commit relay frame
  expected/relay_commit_frame.json   Expected normalized output
```

---

## Part of the Former Lab ecosystem

```
Fortransky  (Fortran TUI Bluesky client)
  └─ relay_raw_tail.py
       └─ assemblersky-harness   ← this project
            └─ x86-64 NASM assembly
```

Fortransky: https://github.com/FormerLab/fortransky
Former Lab: https://bsky.app/profile/formerlab.bsky.social