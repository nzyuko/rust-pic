//! Simple PIC loader -- reads a .bin from disk and executes it.
//!
//! This is a development/testing tool, NOT part of the PIC payload itself.
//! It uses standard WinAPI to allocate RWX memory, copy the payload, and jump.
//!
//! The payload runs on an 8 MB thread to give dinvk's deep call chains
//! (Module::find, syscall!, WinExec → CreateProcess) enough stack headroom.
//!
//! Usage:
//!   cargo run --example loader -- payload.bin

use std::env;
use std::fs;
use std::process;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(addr: *mut u8, size: usize, alloc_type: u32, protect: u32) -> *mut u8;
    fn VirtualFree(addr: *mut u8, size: usize, free_type: u32) -> i32;
}

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: loader <payload.bin>");
        process::exit(1);
    }

    let path = &args[1];
    let payload = match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[-] Failed to read {}: {}", path, e);
            process::exit(1);
        }
    };

    if payload.is_empty() {
        eprintln!("[-] Payload is empty");
        process::exit(1);
    }

    println!("[*] Payload: {} bytes from {}", payload.len(), path);

    // Run payload on a thread with 8 MB stack.
    // The default 1 MB thread stack overflows: dinvk's PEB-walk + indirect
    // syscall resolution + WinExec → CreateProcess is a deep call chain.
    let result = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || run_payload(&payload))
        .expect("failed to spawn loader thread")
        .join()
        .expect("loader thread panicked");

    process::exit(result);
}

fn run_payload(payload: &[u8]) -> i32 {
    unsafe {
        let base = VirtualAlloc(
            std::ptr::null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if base.is_null() {
            eprintln!("[-] VirtualAlloc failed");
            return 1;
        }

        println!("[*] Allocated at {:p}", base);

        std::ptr::copy_nonoverlapping(payload.as_ptr(), base, payload.len());

        println!("[*] Executing payload...");

        let entry: unsafe extern "system" fn() -> u32 = std::mem::transmute(base);
        let status = entry();

        println!("[*] Payload returned: {}", status);
        if status == 0 {
            println!("[+] Success");
        } else {
            println!("[-] Payload returned error code {}", status);
        }

        VirtualFree(base, 0, MEM_RELEASE);
        0
    }
}
