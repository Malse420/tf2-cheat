#!/usr/bin/env python3
"""Find 64-bit signatures for TF2 cheat by searching binaries."""

import struct

TFDIR = (
    "/home/jms/snap/steam/common/.local/share/Steam/steamapps/common/Team Fortress 2"
)


def read_binary(path):
    with open(path, "rb") as f:
        return f.read()


def ida_pattern_to_bytes(pattern):
    """Convert IDA pattern string to list of (byte_or_None) for wildcards."""
    result = []
    parts = pattern.strip().split()
    for p in parts:
        if p == "?" or p == "??":
            result.append(None)
        else:
            result.append(int(p, 16))
    return result


def search_pattern(data, pattern_bytes, max_results=20):
    """Search for IDA-style pattern in data. Returns list of offsets."""
    results = []
    plen = len(pattern_bytes)
    for i in range(len(data) - plen):
        match = True
        for j, pb in enumerate(pattern_bytes):
            if pb is not None and data[i + j] != pb:
                match = False
                break
        if match:
            results.append(i)
            if len(results) >= max_results:
                break
    return results


def bytes_to_hex(data, offset, length=30):
    return " ".join(f"{b:02X}" for b in data[offset : offset + length])


def find_calls(data, offset, count=5):
    """Find E8 (call) instructions near offset and return their targets."""
    results = []
    for i in range(offset, min(offset + 50, len(data) - 5)):
        if data[i] == 0xE8:
            rel = struct.unpack_from("<i", data, i + 1)[0]
            target = i + 5 + rel
            results.append((i, target))
            if len(results) >= count:
                break
    return results


# ============================================================
# 1. StartDrawing in vguimatsurface.so
# Old 32-bit: F3 0F 2A C0 F3 0F 59 45 ? F3 0F 2C C0 89 85 ? ? ? ? E8 ? ? ? ? 8D 4D E4
# Key instructions: cvtsi2ss xmm0,eax; mulss xmm0,[rbp+?]; cvtss2si eax,xmm0
# ============================================================
print("=" * 60)
print("1. Searching for StartDrawing in vguimatsurface.so")
print("=" * 60)
matsurf = read_binary(f"{TFDIR}/bin/linux64/vguimatsurface.so")

# Search for the core sequence: cvtsi2ss + mulss + cvtss2si
# F3 0F 2A C0 = cvtsi2ss xmm0, eax
# F3 0F 59 ?? = mulss xmm0, ???
# F3 0F 2C C0 = cvtss2si eax, xmm0
core_pattern = ida_pattern_to_bytes("F3 0F 2A C0 F3 0F 59 ? ? F3 0F 2C C0")
matches = search_pattern(matsurf, core_pattern)
for m in matches:
    print(f"  Match at 0x{m:x}: {bytes_to_hex(matsurf, m, 40)}")
    calls = find_calls(matsurf, m + 14, 3)
    for c_off, c_target in calls:
        print(f"    Call at +{c_off - m}: -> 0x{c_target:x}")

# ============================================================
# 2. FinishDrawing in vguimatsurface.so
# Old 32-bit: 89 04 24 FF 92 ? ? ? ? 89 34 24 E8 ? ? ? ? 80 7D 97 ? 0F 85 ? ? ? ?
# ============================================================
print("\n" + "=" * 60)
print("2. Searching for FinishDrawing in vguimatsurface.so")
print("=" * 60)
# 89 04 24 = mov [rsp], eax (was mov [esp], eax in 32-bit)
# FF 92 ?? ?? ?? ?? = call [rdx+??] (was call [edx+??])
# 89 34 24 = mov [rsp], esi
# E8 = call
# 80 7D ?? = cmp byte [rbp+??]
finish_pattern = ida_pattern_to_bytes(
    "89 04 24 FF 92 ? ? ? ? 89 34 24 E8 ? ? ? ? 80 7D"
)
matches = search_pattern(matsurf, finish_pattern)
if not matches:
    # Try alternative: in 64-bit it might use rsp instead of esp
    # mov [rsp], eax might be different encoding
    finish_pattern2 = ida_pattern_to_bytes(
        "FF 92 ? ? ? ? 89 34 24 E8 ? ? ? ? 80 7D ? ? 0F 85 ? ? ? ?"
    )
    matches = search_pattern(matsurf, finish_pattern2)
for m in matches:
    print(f"  Match at 0x{m:x}: {bytes_to_hex(matsurf, m, 40)}")

# ============================================================
# 3. bSendPacket in engine.so
# Old 32-bit: BE ? ? ? ? E9 ? ? ? ? 8D B6 00 00 00 00 A1 ? ? ? ? C7 45 ? ? ? ? ? C7 45 ? ? ? ? ? 85 C0 0F 84 ? ? ? ? 8D 55 A8 C7 44 24 ? ? ? ? ?
# BE = mov esi, imm32 (mov esi, address)
# ============================================================
print("\n" + "=" * 60)
print("3. Searching for bSendPacket in engine.so")
print("=" * 60)
engine = read_binary(f"{TFDIR}/bin/linux64/engine.so")

# In 64-bit, mov esi, imm32 is still BE, but the address might be different
# 8D B6 00 00 00 00 = lea esi, [rsi+0] (nop pattern in 32-bit)
# In 64-bit, this might be different. Let's search for the pattern around it
# BE ?? ?? ?? ?? E9 (mov esi, addr; jmp)
bsp_pattern = ida_pattern_to_bytes("BE ? ? ? ? E9 ? ? ? ? 8D B6 00 00 00 00")
matches = search_pattern(engine, bsp_pattern)
if not matches:
    # Try without the lea nop
    bsp_pattern2 = ida_pattern_to_bytes("BE ? ? ? ? E9 ? ? ? ? 0F 1F 00")
    matches = search_pattern(engine, bsp_pattern2)
for m in matches:
    addr = struct.unpack_from("<I", engine, m + 1)[0]
    print(f"  Match at 0x{m:x}: addr=0x{addr:x} {bytes_to_hex(engine, m, 40)}")

# ============================================================
# 4. ClientState in engine.so
# Old 32-bit: C7 04 24 ? ? ? ? E8 ? ? ? ? C7 04 24 ? ? ? ? 89 44 24 04 E8 ? ? ? ? A1 ? ? ? ?
# C7 04 24 = mov [rsp/esp], imm32
# ============================================================
print("\n" + "=" * 60)
print("4. Searching for ClientState in engine.so")
print("=" * 60)
# In 64-bit, mov [rsp], imm32 might be encoded differently
# C7 04 24 = mov dword ptr [rsp], imm32 (same in 64-bit)
# C7 44 24 04 = mov dword ptr [rsp+4], imm32
cs_pattern = ida_pattern_to_bytes(
    "C7 04 24 ? ? ? ? E8 ? ? ? ? C7 04 24 ? ? ? ? 89 44 24 04 E8 ? ? ? ? A1"
)
matches = search_pattern(engine, cs_pattern)
for m in matches:
    addr = struct.unpack_from("<I", engine, m + 3)[0]
    print(f"  Match at 0x{m:x}: addr=0x{addr:x} {bytes_to_hex(engine, m, 40)}")

# ============================================================
# 5. SetPredictionRandomSeed in client.so
# Old 32-bit: 75 7C 31 FF E8 ? ? ? ? 89 B3 ? ? ? ? 89 34 24 E8 ? ? ? ? 89 F8 89 1D ? ? ? ?
# ============================================================
print("\n" + "=" * 60)
print("5. Searching for SetPredictionRandomSeed in client.so")
print("=" * 60)
client = read_binary(f"{TFDIR}/tf/bin/linux64/client.so")

spr_pattern = ida_pattern_to_bytes(
    "75 7C 31 FF E8 ? ? ? ? 89 B3 ? ? ? ? 89 34 24 E8 ? ? ? ? 89 F8"
)
matches = search_pattern(client, spr_pattern)
if not matches:
    # In 64-bit, 89 34 24 (mov [rsp], esi) might be different
    # 89 1D -> mov [rip+?], ebx in 64-bit
    spr_pattern2 = ida_pattern_to_bytes("75 ? 31 FF E8 ? ? ? ? 89 B3 ? ? ? ?")
    matches = search_pattern(client, spr_pattern2)
for m in matches:
    print(f"  Match at 0x{m:x}: {bytes_to_hex(client, m, 40)}")
    calls = find_calls(client, m + 4, 3)
    for c_off, c_target in calls:
        print(f"    Call at +{c_off - m}: -> 0x{c_target:x}")

# ============================================================
# 6. MD5_PseudoRandom in client.so
# Old 32-bit: 8B 45 08 F3 0F 11 80 ? ? ? ? 8B 45 0C 89 04 24 E8 ? ? ? ? 25 ? ? ? ? 89 43 34 E8 ? ? ? ?
# ============================================================
print("\n" + "=" * 60)
print("6. Searching for MD5_PseudoRandom in client.so")
print("=" * 60)
# 8B 45 08 = mov eax, [rbp+8] (in 64-bit might be mov eax, [rbp+0x10] due to 8-byte args)
# F3 0F 11 80 = movss [rax+?], xmm0
md5_pattern = ida_pattern_to_bytes(
    "F3 0F 11 80 ? ? ? ? 89 04 24 E8 ? ? ? ? 25 ? ? ? ? 89 43 34"
)
matches = search_pattern(client, md5_pattern)
if not matches:
    # Try with different register patterns
    md5_pattern2 = ida_pattern_to_bytes(
        "F3 0F 11 80 ? ? ? ? ? 04 24 E8 ? ? ? ? 25 ? ? ? ? 89 43 34"
    )
    matches = search_pattern(client, md5_pattern2)
for m in matches:
    print(f"  Match at 0x{m:x}: {bytes_to_hex(client, m, 40)}")

# ============================================================
# 7. IsPlayerOnSteamFriendsList in client.so
# Old 32-bit: 55 89 E5 56 53 81 EC ? ? ? ? 65 A1 ? ? ? ? 89 45 F4 31 C0 8B 5D 0C E8 ? ? ? ? 85 C0 74 48 85 DB 74 44
# 55 = push rbp; 89 E5 = mov ebp, esp (32-bit prologue)
# In 64-bit: 55 = push rbp; 48 89 E5 = mov rbp, rsp
# ============================================================
print("\n" + "=" * 60)
print("7. Searching for IsPlayerOnSteamFriendsList in client.so")
print("=" * 60)
# 64-bit prologue: 55 48 89 E5
friends_pattern = ida_pattern_to_bytes("55 48 89 E5 ? ? ? ? 65 ? ? ? ? ? ? ? ? 31 C0")
matches = search_pattern(client, friends_pattern)
if not matches:
    # Try broader search
    friends_pattern2 = ida_pattern_to_bytes(
        "55 48 89 E5 56 53 48 81 EC ? ? ? ? 65 48 ? ? ? ? ? ? 31 C0"
    )
    matches = search_pattern(client, friends_pattern2)
for m in matches:
    print(f"  Match at 0x{m:x}: {bytes_to_hex(client, m, 50)}")

print("\n" + "=" * 60)
print("Done!")
print("=" * 60)
