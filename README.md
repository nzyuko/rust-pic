# rust-pic

A Rust shellcode builder for Windows.

It builds a small PIC-style Rust payload, checks the PE wrapper, and extracts the bytes into `payload.bin`.

The normal build is just for quick development. The PIC build is the one used for shellcode output.

The code keeps the important parts in one place: the custom entry point, the `no_std` build, the PEB walk, export lookup, indirect syscall demo, and payload extraction.

## build

Normal build:

```powershell
cargo build --release
```

Shellcode build:

```powershell
cargo build --release --features pic
```

Extract shellcode bytes:

```powershell
python tools\validate_pic.py target\release\pic_example.exe -o payload.bin
```

## test

Run the extracted shellcode with the local loader:

```powershell
cargo run --example loader -- payload.bin
```

The loader is only a small test harness. It allocates memory, copies the payload, and calls it so the build can be checked locally.

Blog: https://zer0.art/2026/05/28/writing-pic-in-rust/
