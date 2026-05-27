//! Rust PIC (Position-Independent Code) payload.
//!
//! True PIC shellcode — zero imports, zero relocations, single .text section.
//! Everything resolved at runtime from the PEB.
//!
//! Uses [dinvk](https://github.com/joaoviictorti/dinvk) for PEB walking
//! and indirect syscalls.
//!
//! Two build modes:
//!   Normal:  cargo build --release           (with CRT, println! diagnostics)
//!   PIC:     cargo build --release --features pic  (no CRT, custom entry, single section)
//!
//! Extract:
//!   python tools/validate_pic.py target/release/pic_example.exe -o payload.bin

// In PIC mode we still compile with std (dinvk's deps require it at compile time)
// but /NODEFAULTLIB strips the CRT at link time. The resulting binary has zero
// runtime dependency on std — all API resolution goes through PEB walk.
#![cfg_attr(feature = "pic", no_main)]

use core::ffi::c_void;
use core::ptr::null_mut;

// ── Context struct: all mutable state in one heap allocation ────────────────
//
// In PIC code you cannot use static mut variables -- they live in .text after
// section merging. Writing to them faults. All mutable state goes on the heap.
#[repr(C, align(64))]
struct PicCtx {
    heap_handle: usize,
    fn_heap_alloc: usize,
    fn_heap_free: usize,
    alloc_base: *mut c_void,
    alloc_size: usize,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Normal mode: main() harness with println! output for development/testing
// ═══════════════════════════════════════════════════════════════════════════════
#[cfg(not(feature = "pic"))]
fn main() {
    println!("[*] Rust PIC technique demonstration (normal mode)");
    println!("[*] Build with --features pic for true PIC payload\n");
    unsafe { pic_core() };
    println!("\n[*] All techniques demonstrated successfully");
}

// ═══════════════════════════════════════════════════════════════════════════════
// PIC mode: custom entry point — /NODEFAULTLIB strips CRT, /ENTRY points here
// ═══════════════════════════════════════════════════════════════════════════════
#[cfg(feature = "pic")]
#[no_mangle]
pub unsafe extern "system" fn _pic_entry() -> u32 {
    pic_core();
    0
}

// ═══════════════════════════════════════════════════════════════════════════════
// Core PIC logic — shared between normal and PIC modes
// ═══════════════════════════════════════════════════════════════════════════════
unsafe fn pic_core() {
    // ── TECHNIQUE 1: PEB Walking ────────────────────────────────────────
    //
    // On x64 Windows, gs:[0x60] points to the PEB. From here we walk
    // loaded modules and resolve any export without a single API call.

    let peb: usize;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem));

    if peb == 0 {
        return;
    }

    // PEB+0x30 = ProcessHeap on x64
    let process_heap = *((peb + 0x30) as *const usize);
    if process_heap == 0 {
        return;
    }

    // ── TECHNIQUE 2: Dynamic Module Resolution (no LoadLibrary, no IAT) ─
    //
    // dinvk::Module::find() walks PEB → PEB_LDR_DATA → InMemoryOrderModuleList.
    // Pure memory reads, no API calls.

    let ntdll = match dinvk::Module::find("ntdll.dll") {
        Some(m) => m,
        None => return,
    };

    // ── TECHNIQUE 3: Export Resolution by Name ──────────────────────────
    //
    // Parse IMAGE_EXPORT_DIRECTORY directly. No GetProcAddress.

    type RtlAllocateHeapFn = unsafe extern "system" fn(usize, u32, usize) -> *mut c_void;
    type RtlFreeHeapFn = unsafe extern "system" fn(usize, u32, *mut c_void) -> u32;

    let fn_alloc: RtlAllocateHeapFn = match ntdll.proc("RtlAllocateHeap") {
        Some(p) => core::mem::transmute(p),
        None => return,
    };
    let fn_free: RtlFreeHeapFn = match ntdll.proc("RtlFreeHeap") {
        Some(p) => core::mem::transmute(p),
        None => return,
    };

    // ── TECHNIQUE 4: Heap-Allocated Context (no globals) ────────────────
    //
    // All mutable state in a single heap struct. No static mut.

    let ctx_size = core::mem::size_of::<PicCtx>();
    let ctx_ptr = fn_alloc(process_heap, 0x08 /* HEAP_ZERO_MEMORY */, ctx_size);
    if ctx_ptr.is_null() {
        return;
    }

    let ctx = &mut *(ctx_ptr as *mut PicCtx);
    ctx.heap_handle = process_heap;
    ctx.fn_heap_alloc = fn_alloc as usize;
    ctx.fn_heap_free = fn_free as usize;

    // ── TECHNIQUE 5: Indirect Syscalls ──────────────────────────────────
    //
    // Resolve SSN from ntdll stub (Hell's / Halo's / Tartarus Gate),
    // execute syscall from inside ntdll. Return address points into ntdll.

    let mut addr: *mut c_void = null_mut();
    let mut size: usize = 0x1000;

    let status = dinvk::syscall!(
        "NtAllocateVirtualMemory",
        -1isize as *mut c_void,  // NtCurrentProcess()
        &mut addr as *mut _,
        0usize,                   // ZeroBits
        &mut size as *mut _,
        0x3000u32,               // MEM_COMMIT | MEM_RESERVE
        0x04u32                  // PAGE_READWRITE
    );

    match status {
        Ok(0) => {
            ctx.alloc_base = addr;
            ctx.alloc_size = size;
        }
        _ => {
            fn_free(process_heap, 0, ctx_ptr);
            return;
        }
    }

    // Write a marker to prove the allocation worked
    if !addr.is_null() {
        let marker = b"PIC_OK\0";
        core::ptr::copy_nonoverlapping(marker.as_ptr(), addr as *mut u8, marker.len());
    }

    // ── TECHNIQUE 6: Dynamic WinAPI Resolution ──────────────────────────
    //
    // Resolve and call any WinAPI without IAT entries.

    if let Some(k32) = dinvk::Module::find("kernel32.dll") {
        type GetCurrentProcessIdFn = unsafe extern "system" fn() -> u32;
        let _ = dinvk::dinvoke!(k32, "GetCurrentProcessId", GetCurrentProcessIdFn,);
    }

    // ── TECHNIQUE 7: Hash-Based Resolution ──────────────────────────────
    //
    // Replace string lookups with compile-time hashes — no API name
    // strings visible in the binary.

    let _ntdll_by_hash = dinvk::Module::find_by_hash(
        0x1C8BDEBA, // crc32ba("NTDLL.DLL")
        dinvk::hash::crc32ba,
    );

    // ── CLEANUP: Free allocations, zero-wipe context ────────────────────

    if !ctx.alloc_base.is_null() {
        let mut free_addr = ctx.alloc_base;
        let mut free_size: usize = 0;
        let _ = dinvk::syscall!(
            "NtFreeVirtualMemory",
            -1isize as *mut c_void,
            &mut free_addr as *mut _,
            &mut free_size as *mut _,
            0x8000u32  // MEM_RELEASE
        );
    }

    // Zero-wipe context before freeing (prevents forensic recovery)
    core::ptr::write_bytes(ctx_ptr as *mut u8, 0, ctx_size);
    fn_free(process_heap, 0, ctx_ptr);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Compiler intrinsics (PIC mode only)
// ═══════════════════════════════════════════════════════════════════════════════
//
// With /NODEFAULTLIB, the CRT is gone. LLVM still emits calls to these.

#[cfg(feature = "pic")]
#[allow(non_upper_case_globals)]
#[no_mangle]
pub static _tls_index: u32 = 0;

#[cfg(feature = "pic")]
mod pic_intrinsics {
    #[no_mangle]
    pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
        let mut len = 0;
        while *s.add(len) != 0 {
            len += 1;
        }
        len
    }

    #[no_mangle]
    pub unsafe extern "C" fn __CxxFrameHandler3() -> i32 {
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        let mut i = 0;
        while i < n {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        dst
    }

    #[no_mangle]
    pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
        let mut i = 0;
        while i < n {
            *dst.add(i) = val as u8;
            i += 1;
        }
        dst
    }

    #[no_mangle]
    pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
        let mut i = 0;
        while i < n {
            let diff = (*a.add(i) as i32) - (*b.add(i) as i32);
            if diff != 0 {
                return diff;
            }
            i += 1;
        }
        0
    }
}

// ── Stack probe (PIC mode only) ─────────────────────────────────────────────
//
// Windows x64 ABI: probe each page when stack frame exceeds 4KB.
#[cfg(feature = "pic")]
core::arch::global_asm!(
    ".globl __chkstk",
    "__chkstk:",
    "push rcx",
    "push rax",
    "cmp  rax, 0x1000",
    "lea  rcx, [rsp + 24]",
    "jb   4f",
    "3:",
    "sub  rcx, 0x1000",
    "test byte ptr [rcx], 0",
    "sub  rax, 0x1000",
    "cmp  rax, 0x1000",
    "ja   3b",
    "4:",
    "sub  rcx, rax",
    "test byte ptr [rcx], 0",
    "pop  rax",
    "pop  rcx",
    "ret",
);
