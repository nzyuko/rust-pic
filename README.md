# rust-pic

Rust position-independent code for Windows.

This repo is the source that backs the write-up:

https://zer0.art/2026/05/28/writing-pic-in-rust/

The goal is to make the shellcode/PIC build process easier to see. A normal Rust executable gets a lot of help from the Windows loader. Shellcode does not. These examples show what has to move into the payload when the bytes need to run from wherever they land in memory.

## What It Shows

`rust-pic` has two build modes.

The normal mode is a regular Rust executable. It is useful while developing because you still get normal Rust startup and console output.

The PIC mode is the interesting one. It builds with `no_std`, uses a custom entry point, merges data into `.text`, removes the normal C runtime path, walks the PEB, resolves exports manually, and extracts the useful bytes into a flat payload.

The implementation demonstrates:

- PEB walking to find loaded modules.
- Manual export parsing instead of `GetProcAddress`.
- No loader-filled import table in the final PIC path.
- A heap-backed context instead of writable globals.
- A small indirect syscall trampoline.
- A hash-based module lookup example.
- A validator/extractor that turns the PE wrapper into `payload.bin`.

## Repo Layout

`src/main.rs` contains the normal-mode harness and the PIC payload logic.

`build.rs` changes linker behavior when the `pic` feature is enabled.

`tools/validate_pic.py` checks the PIC-mode PE and extracts a flat payload.

`examples/loader.rs` is a small Windows loader for local testing in a controlled VM.

## Build

Use a Windows Rust toolchain for the PIC build. The linker flags in `build.rs` are MSVC-style flags, so the intended target is Windows/MSVC.

Normal development build:

```powershell
cargo build --release
```

PIC build:

```powershell
cargo build --release --features pic
```

Extract the payload:

```powershell
python tools\validate_pic.py target\release\pic_example.exe -o payload.bin
```

The validator prints the PE layout, checks the properties that matter for this demo, and writes the extracted payload. The output is not the full PE file. It is the useful `.text` bytes with a small trampoline at the front so offset zero can be called directly.

## Local Test

After extraction, the loader example can run the payload in a local Windows VM:

```powershell
cargo run --example loader -- payload.bin
```

The loader is not part of the payload. It only allocates memory, copies the bytes, and calls the payload so the build can be tested without writing a separate harness.

## Notes

This is a learning build. Some names are intentionally left readable so the flow is easy to follow in PE-bear and in the source. The point is to understand the moving parts: entry point, section layout, PEB walk, export parsing, syscall setup, and extraction.

For the full visual walkthrough, read the blog post:

https://zer0.art/2026/05/28/writing-pic-in-rust/
