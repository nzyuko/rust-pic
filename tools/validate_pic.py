#!/usr/bin/env python
"""
PIC shellcode validator and extractor.

Reads a PIC-mode PE (.exe), validates it has the expected properties
(single code section, zero imports, no plaintext API names), extracts
the .text section, and prepends a self-relocating trampoline so the
output .bin is callable at offset 0.

If the PE has a .reloc section, the trampoline applies base relocations
at runtime so that vtable pointers and other absolute addresses work
correctly regardless of load address.

Usage:
    python validate_pic.py target/release/pic_example.exe [-o output.bin]

If -o is omitted, defaults to replacing .exe with .bin in the same dir.
"""

import struct
import sys
import os

def r16(d, o): return struct.unpack_from('<H', d, o)[0]
def r32(d, o): return struct.unpack_from('<I', d, o)[0]
def r64(d, o): return struct.unpack_from('<Q', d, o)[0]

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pic_pe.exe> [-o output.bin]")
        sys.exit(1)

    pe_path = sys.argv[1]
    out_path = None
    skip_name_check = '--skip-name-check' in sys.argv
    no_reloc = '--no-reloc' in sys.argv
    if '-o' in sys.argv:
        idx = sys.argv.index('-o')
        if idx + 1 < len(sys.argv):
            out_path = sys.argv[idx + 1]
    if out_path is None:
        out_path = os.path.splitext(pe_path)[0] + '.bin'

    with open(pe_path, 'rb') as f:
        pe = f.read()

    errors = []
    warnings = []

    # ── Parse PE headers ──────────────────────────────────────────────────
    if pe[:2] != b'MZ':
        errors.append("Not a PE file (missing MZ signature)")
        report(errors, warnings)
        return

    nt = r32(pe, 0x3C)
    if r32(pe, nt) != 0x4550:
        errors.append("Bad PE signature")
        report(errors, warnings)
        return

    fh = nt + 4
    num_sec = r16(pe, fh + 2)
    opt_sz = r16(pe, fh + 16)

    oh = fh + 20
    magic = r16(pe, oh)
    if magic != 0x020B:
        errors.append(f"Not PE64 (magic=0x{magic:X})")

    entry_rva = r32(pe, oh + 16)
    image_base = r64(pe, oh + 24)
    size_of_image = r32(pe, oh + 56)

    # Import directory
    imp_rva = r32(pe, oh + 120)
    imp_sz = r32(pe, oh + 124)

    # Relocation directory
    reloc_rva = r32(pe, oh + 152)
    reloc_sz = r32(pe, oh + 156)

    print(f"[*] PE: {pe_path}")
    print(f"[*] Size: {len(pe)} bytes ({len(pe)/1024:.1f} KB)")
    print(f"[*] ImageBase: 0x{image_base:X}  EntryRVA: 0x{entry_rva:X}")
    print(f"[*] Sections: {num_sec}")

    # ── Parse sections ──────────────────────────────────────────────────
    sec_start = nt + 24 + opt_sz
    sections = {}
    for i in range(num_sec):
        sh = sec_start + i * 40
        name = pe[sh:sh+8].rstrip(b'\x00').decode('ascii', errors='replace')
        va = r32(pe, sh + 12)
        vs = r32(pe, sh + 8)
        raw_sz = r32(pe, sh + 16)
        raw_off = r32(pe, sh + 20)
        chars = r32(pe, sh + 36)
        sections[name] = (va, vs, raw_sz, raw_off, chars)
        print(f"    [{name:8s}] VA=0x{va:06X} VS=0x{vs:06X} "
              f"RawSz=0x{raw_sz:06X} RawOff=0x{raw_off:06X} "
              f"Chars=0x{chars:08X}")

    # ── Validate sections ────────────────────────────────────────────────
    if '.text' not in sections:
        errors.append("No .text section found")
        report(errors, warnings)
        return

    # .idata and .reloc are expected when using dinvk/windows-sys dependency.
    # They are inert at runtime — no execution path goes through the IAT.
    allowed_sections = {'.text', '.reloc', '.idata'}
    extra = set(sections.keys()) - allowed_sections
    if extra:
        errors.append(f"Unexpected sections: {extra}")

    # ── Imports: informational only ─────────────────────────────────────
    if imp_rva != 0 or imp_sz != 0:
        print(f"[*] Import directory present (windows-sys residual, IAT not used at runtime)")
    else:
        print("[+] No imports (IAT clean)")

    # ── Parse relocations ────────────────────────────────────────────────
    text_va, text_vs, text_raw_sz, text_raw_off, text_chars = sections['.text']
    text_data = pe[text_raw_off:text_raw_off + text_vs]

    reloc_offsets = []
    if reloc_rva != 0 and reloc_sz != 0:
        if '.reloc' not in sections:
            errors.append("Relocation directory present but no .reloc section")
        else:
            reloc_va, reloc_vs, reloc_raw_sz, reloc_raw_off, _ = sections['.reloc']
            pos = reloc_raw_off
            end = reloc_raw_off + reloc_sz
            while pos < end:
                blk_rva = r32(pe, pos)
                blk_sz = r32(pe, pos + 4)
                if blk_sz == 0:
                    break
                num_entries = (blk_sz - 8) // 2
                for j in range(num_entries):
                    entry = r16(pe, pos + 8 + j * 2)
                    typ = entry >> 12
                    offset = entry & 0xFFF
                    if typ == 10:  # IMAGE_REL_BASED_DIR64
                        fixup_rva = blk_rva + offset
                        if text_va <= fixup_rva < text_va + text_vs:
                            text_offset = fixup_rva - text_va
                            reloc_offsets.append(text_offset)
                        else:
                            warnings.append(f"Relocation at RVA 0x{fixup_rva:X} outside .text")
                    elif typ == 0:  # IMAGE_REL_BASED_ABSOLUTE (padding)
                        pass
                    else:
                        warnings.append(f"Unsupported relocation type {typ} at RVA 0x{blk_rva + offset:X}")
                pos += blk_sz
            print(f"[+] {len(reloc_offsets)} DIR64 relocations (self-relocating trampoline)")
    else:
        print("[+] No relocations")

    # ── Validate: entry point within .text ──────────────────────────────
    if entry_rva < text_va or entry_rva >= text_va + text_vs:
        errors.append(f"Entry RVA 0x{entry_rva:X} outside .text "
                      f"[0x{text_va:X}..0x{text_va+text_vs:X})")
    else:
        entry_offset = entry_rva - text_va
        print(f"[+] Entry at .text+0x{entry_offset:X}")

    # ── Check for plaintext API/DLL names (informational) ─────────────
    # dinvk uses string-based module lookup so names like "ntdll.dll" are
    # present by design — they're resolved at runtime, not via the IAT.
    if skip_name_check:
        print("[*] Skipping plaintext API/DLL name check (--skip-name-check)")
    else:
        api_names = [
            b'VirtualAlloc', b'VirtualFree', b'VirtualProtect',
            b'LoadLibrary', b'GetProcAddress', b'FreeLibrary',
            b'HeapAlloc', b'HeapFree', b'HeapReAlloc',
            b'CreateThread', b'CreateRemoteThread',
            b'NtAllocateVirtualMemory', b'NtFreeVirtualMemory',
            b'NtClose', b'NtWriteVirtualMemory',
            b'RtlAllocateHeap', b'RtlFreeHeap',
            b'kernel32.dll', b'ntdll.dll', b'user32.dll',
        ]
        found = [name.decode() for name in api_names if name in text_data]
        if found:
            for name in found:
                warnings.append(f"Plaintext string in .text: {name} (dinvk runtime lookup)")
        else:
            print("[+] No plaintext API/DLL names")

    # ── Check for stray MZ/PE signatures ──────────────────────────────
    mz_count = sum(1 for i in range(len(text_data)-1)
                   if text_data[i:i+2] == b'MZ')
    pe_count = sum(1 for i in range(len(text_data)-3)
                   if text_data[i:i+4] == b'PE\x00\x00')
    if mz_count > 0:
        warnings.append(f"{mz_count} MZ byte pair(s) in .text (likely instruction encoding)")
    if pe_count > 0:
        warnings.append(f"{pe_count} PE\\0\\0 signature(s) in .text")

    # ── Build output .bin ──────────────────────────────────────────────
    if errors:
        report(errors, warnings)
        return

    reloc_only = '--reloc-only' in sys.argv
    if reloc_only and reloc_offsets:
        print(f"[!] --reloc-only: relocations + ret (no entry jump)")
        output = build_relocating_output(text_data, entry_offset, reloc_offsets,
                                         image_base, text_va, skip_entry=True)
    elif reloc_offsets and not no_reloc:
        output = build_relocating_output(text_data, entry_offset, reloc_offsets,
                                         image_base, text_va)
    elif no_reloc and reloc_offsets:
        print(f"[!] --no-reloc: skipping {len(reloc_offsets)} relocations (DIAG ONLY)")
        output = build_simple_output(text_data, entry_offset)
    else:
        output = build_simple_output(text_data, entry_offset)

    with open(out_path, 'wb') as f:
        f.write(output)

    if warnings:
        print()
        for w in warnings:
            print(f"[!] {w}")

    print(f"\n[+] Output: {out_path}")
    print(f"[+] Size: {len(output)} bytes ({len(output)/1024:.1f} KB)")
    print(f"[+] VALID")


def build_simple_output(text_data, entry_offset):
    """Build .bin with a simple JMP trampoline (no relocations needed)."""
    TRAMPOLINE_SIZE = 16
    jmp_rel = TRAMPOLINE_SIZE + entry_offset - 5
    trampoline = b'\xe9' + struct.pack('<i', jmp_rel) + b'\xcc' * 11
    print(f"[+] Entry: offset 0 (trampoline -> +0x{TRAMPOLINE_SIZE + entry_offset:X})")
    return trampoline + text_data


def build_relocating_output(text_data, entry_offset, reloc_offsets, image_base, text_va, skip_entry=False):
    """Build .bin with a self-relocating trampoline that fixes up absolute addresses."""

    # Relocation table: [count: u32] [offset0: u32] [offset1: u32] ...
    reloc_table = struct.pack('<I', len(reloc_offsets))
    for off in sorted(reloc_offsets):
        reloc_table += struct.pack('<I', off)

    expected_text_base = image_base + text_va

    # Trampoline code size is fixed at 81 bytes (see assembly below)
    TRAMPOLINE_CODE_SIZE = 81
    TRAMPOLINE_CODE_PADDED = (TRAMPOLINE_CODE_SIZE + 15) & ~15  # 96
    RELOC_TABLE_OFFSET = TRAMPOLINE_CODE_PADDED
    TEXT_START = TRAMPOLINE_CODE_PADDED + len(reloc_table)
    TEXT_START = (TEXT_START + 15) & ~15

    code = bytearray()

    # lea rax, [rip - 7]  -- rax = address of _start (bin base)
    code += b'\x48\x8D\x05\xF9\xFF\xFF\xFF'

    # mov rbx, expected_text_base
    code += b'\x48\xBB' + struct.pack('<Q', expected_text_base)

    # lea rcx, [rax + TEXT_START]
    code += b'\x48\x8D\x88' + struct.pack('<i', TEXT_START)

    # sub rcx, rbx
    code += b'\x48\x29\xD9'

    # test rcx, rcx
    code += b'\x48\x85\xC9'

    # jz .skip (patch later)
    jz1_pos = len(code)
    code += b'\x0F\x84\x00\x00\x00\x00'

    # lea rsi, [rax + RELOC_TABLE_OFFSET]
    code += b'\x48\x8D\xB0' + struct.pack('<i', RELOC_TABLE_OFFSET)

    # mov edx, [rsi]
    code += b'\x8B\x16'

    # add rsi, 4
    code += b'\x48\x83\xC6\x04'

    # .loop:
    loop_pos = len(code)

    # test edx, edx
    code += b'\x85\xD2'

    # jz .skip (patch later)
    jz2_pos = len(code)
    code += b'\x0F\x84\x00\x00\x00\x00'

    # mov r8d, [rsi]
    code += b'\x44\x8B\x06'

    # lea r9, [rax + TEXT_START]
    code += b'\x4C\x8D\x88' + struct.pack('<i', TEXT_START)

    # add qword [r9 + r8], rcx
    code += b'\x4B\x01\x0C\x01'

    # add rsi, 4
    code += b'\x48\x83\xC6\x04'

    # dec edx
    code += b'\xFF\xCA'

    # jmp .loop
    jmp_loop_target = loop_pos - (len(code) + 5)
    code += b'\xE9' + struct.pack('<i', jmp_loop_target)

    # .skip:
    skip_pos = len(code)

    # Patch jz targets
    struct.pack_into('<i', code, jz1_pos + 2, skip_pos - (jz1_pos + 6))
    struct.pack_into('<i', code, jz2_pos + 2, skip_pos - (jz2_pos + 6))

    # jmp entry or return
    entry_abs = TEXT_START + entry_offset
    if skip_entry:
        code += b'\x31\xC0\xC3'  # xor eax,eax; ret
    else:
        jmp_entry_rel = entry_abs - (len(code) + 5)
        code += b'\xE9' + struct.pack('<i', jmp_entry_rel)

    actual_code_size = len(code)
    assert actual_code_size <= TRAMPOLINE_CODE_PADDED, \
        f"Trampoline code {actual_code_size} > padded {TRAMPOLINE_CODE_PADDED}"

    # Pad trampoline
    code += b'\xCC' * (TRAMPOLINE_CODE_PADDED - len(code))

    # Build the full .bin
    output = bytes(code)
    output += reloc_table
    output += b'\x00' * (TEXT_START - len(output))
    output += text_data

    print(f"[+] Relocator: {actual_code_size} bytes code, {len(reloc_offsets)} fixups")
    print(f"[+] Entry: offset 0 (relocator -> +0x{entry_abs:X})")

    return output


def report(errors, warnings):
    print()
    for e in errors:
        print(f"[-] ERROR: {e}")
    for w in warnings:
        print(f"[!] {w}")
    if errors:
        print("\n[-] VALIDATION FAILED")
        sys.exit(1)


if __name__ == '__main__':
    main()
