#!/usr/bin/env python3
"""Static stack-usage report for an SBF program binary.

SBF (SBPF v0-v2) gives every function a fixed 4 KiB stack frame addressed
relative to r10; call depth is limited to 64 frames. This script disassembles
the program with the platform-tools llvm-objdump, splits it into functions
(at call targets), and reports the deepest r10-relative offset used by each
function. Any offset > 4096 would be undefined behaviour (cargo-build-sbf
already rejects these at link time; this report gives the margin).

Usage: scripts/sbf-stack-report.py target/deploy/<program>.so [--objdump PATH]
"""
import json
import os
import re
import subprocess
import sys

FRAME = 4096
# Outgoing-argument area: up to five extra 8-byte arguments.
ABI_ARG_AREA = 40


def main():
    so = sys.argv[1]
    objdump = None
    if "--objdump" in sys.argv:
        objdump = sys.argv[sys.argv.index("--objdump") + 1]
    if objdump is None:
        base = os.path.expanduser("~/.cache/solana")
        versions = sorted(d for d in os.listdir(base) if d.startswith("v1."))
        objdump = os.path.join(base, versions[-1], "platform-tools/llvm/bin/llvm-objdump")
    flags = subprocess.run(["readelf", "-h", so], capture_output=True, text=True, check=True).stdout
    m = re.search(r"Flags:\s+0x([0-9a-f]+)", flags)
    sbpf = int(m.group(1), 16) if m else 0
    if sbpf >= 3:
        print(json.dumps({"binary": so, "sbpf_version": sbpf, "note": "static frame analysis only implemented for SBPF v0-v2 frame layout; rebuild with --arch v0 for this report. cargo-build-sbf's own stack-offset check still applies."}, indent=2))
        return 0
    out = subprocess.run([objdump, "-d", "--no-show-raw-insn", so], capture_output=True, text=True, check=True).stdout

    insns = []  # (addr, text)
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(.*)$", line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2).strip()))
    # Function starts: entry of .text plus every internal call target.
    starts = {insns[0][0]} if insns else set()
    for addr, text in insns:
        m = re.match(r"call (-?0x[0-9a-f]+|-?\d+)$", text)
        if m:
            imm = int(m.group(1), 0)
            if imm != -1:  # -1 = syscall placeholder resolved at load time
                starts.add(addr + 8 + imm * 8)
    starts = sorted(starts)

    funcs = {}
    abi_slots = 0
    cur = None
    for addr, text in insns:
        if addr in starts:
            cur = addr
            funcs[cur] = 0
        for m in re.finditer(r"r10 - 0x([0-9a-f]+)", text):
            off = int(m.group(1), 16)
            if FRAME - ABI_ARG_AREA < off <= FRAME and text.startswith("st"):
                # SBF calling convention: arguments beyond the fifth are
                # written to the lowest bytes of the caller's frame, where
                # the callee reads them. They are part of the frame, not
                # locals, so they are reported separately.
                abi_slots += 1
                continue
            funcs[cur] = max(funcs[cur], off)
        m = re.match(r"add64 r\d, -0x([0-9a-f]+)$", text)
        # (frame-relative pointers are formed as `mov rX, r10; add64 rX, -off`)
        if m and prev_was_r10_mov:
            funcs[cur] = max(funcs[cur], int(m.group(1), 16))
        prev_was_r10_mov = bool(re.match(r"mov64 r\d, r10$", text))

    sizes = sorted(funcs.values(), reverse=True)
    report = {
        "binary": so,
        "sbpf_version": sbpf,
        "functions": len(funcs),
        "frame_limit_bytes": FRAME,
        "max_frame_offset_bytes": sizes[0] if sizes else 0,
        "top_10_frame_offsets": sizes[:10],
        "functions_over_limit": sum(1 for s in sizes if s > FRAME),
        "abi_argument_spill_stores": abi_slots,
    }
    print(json.dumps(report, indent=2))
    return 1 if report["functions_over_limit"] else 0


prev_was_r10_mov = False
if __name__ == "__main__":
    sys.exit(main())
