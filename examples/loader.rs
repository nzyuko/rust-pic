//! Simple PIC loader -- reads a .bin from disk and executes it.
//!
//! This is a development/testing tool, NOT part of the PIC payload itself.
//! It uses standard WinAPI to allocate RWX memory, copy the payload, and jump.
//!
//! Usage:
//!   cargo run --example loader -- payload.bin

use std::env;
use std::fs;
use std::process;

// We use the Windows API directly here because the *loader* is a normal
// binary -- only the *payload* needs to be position-independent.
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

    unsafe {
        // Allocate RWX memory for the payload
        let base = VirtualAlloc(
            std::ptr::null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if base.is_null() {
            eprintln!("[-] VirtualAlloc failed");
            process::exit(1);
        }

        println!("[*] Allocated at {:p}", base);

        // Copy payload into executable memory
        std::ptr::copy_nonoverlapping(payload.as_ptr(), base, payload.len());

        println!("[*] Executing payload...");

        // Cast to function pointer and call
        // The PIC entry returns a u32 status code (0 = success)
        let entry: unsafe extern "system" fn() -> u32 = std::mem::transmute(base);
        let status = entry();

        println!("[*] Payload returned: {}", status);
        if status == 0 {
            println!("[+] Success");
        } else {
            println!("[-] Payload returned error code {}", status);
        }

        // Free the allocation
        VirtualFree(base, 0, MEM_RELEASE);
    }
}
