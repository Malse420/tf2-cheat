#!/usr/bin/env python3
"""Fast signature scanner for 64-bit TF2 binaries."""
import re, struct
TFDIR = "/home/jms/snap/steam/common/.local/share/Steam/steamapps/common/Team Fortress 2"

def load(p):
    with open(p, "rb") as f: return f.read()

def scan(data, pat, mx=10):
    rx = b""
    for t in pat.split():
        rx += b"." if t in ("?","??") else re.escape(bytes([int(t,16)]))
    return [m.start() for m in re.compile(rx, re.DOTALL).finditer(data)]

def hd(data, off, n=48):
    return " ".join("%02X" % b for b in data[off:off+n])

def calls(data, off, n=5, w=80):
    r = []
    for i in range(off, min(off+w, len(data)-5)):
        if data[i] == 0xE8:
            rel = struct.unpack_from("<i", data, i+1)[0]
            r.append((i, i+5+rel))
            if len(r) >= n: break
    return r

def riprel(data, off, w=80):
    r = []
    for i in range(off, min(off+w, len(data)-7)):
        if data[i]==0x48 and data[i+1] in (0x8B,0x8D) and data[i+2]==0x05:
            d=struct.unpack_from("<i",data,i+3)[0]; r.append((i,i+7+d))
        elif data[i]==0x8B and data[i+1]==0x05:
            d=struct.unpack_from("<i",data,i+2)[0]; r.append((i,i+6+d))
    return r

ms = load(TFDIR+"/bin/linux64/vguimatsurface.so")
en = load(TFDIR+"/bin/linux64/engine.so")
cl = load(TFDIR+"/tf/bin/linux64/client.so")

print("=== vguimatsurface.so (%d) ===" % len(ms))
for lbl,pat in [("StartDrawing core","F3 0F 2A C0 F3 0F 59 45 ? F3 0F 2C C0"),
                ("StartDrawing old+call","F3 0F 2A C0 F3 0F 59 45 ? F3 0F 2C C0 89 85 ? ? ? ? E8"),
                ("FinishDrawing old","89 04 24 FF 92 ? ? ? ? 89 34 24 E8 ? ? ? ? 80 7D"),
                ("FinishDrawing partial","89 04 24 FF 92 ? ? ? ? 89 34 24 E8")]:
    r = scan(ms, pat)
    print("\n[%s] %d matches" % (lbl, len(r)))
    for m in r[:4]:
        print("  0x%x: %s" % (m, hd(ms, m)))
        for co,ct in calls(ms, m+14, 3): print("    call +0x%x -> 0x%x" % (co-m, ct))

print("\n=== engine.so (%d) ===" % len(en))
for lbl,pat in [("bSendPacket old","BE ? ? ? ? E9 ? ? ? ? 8D B6 00 00 00 00"),
                ("ClientState old","C7 04 24 ? ? ? ? E8 ? ? ? ? C7 04 24 ? ? ? ? 89 44 24 04 E8 ? ? ? ? A1")]:
    r = scan(en, pat)
    print("\n[%s] %d matches" % (lbl, len(r)))
    for m in r[:4]: print("  0x%x: %s" % (m, hd(en, m)))

print("\n=== client.so (%d) ===" % len(cl))
for lbl,pat in [("SetPredRandomSeed old","75 7C 31 FF E8 ? ? ? ? 89 B3 ? ? ? ? 89 34 24 E8 ? ? ? ? 89 F8"),
                ("MD5_PseudoRandom old","8B 45 08 F3 0F 11 80 ? ? ? ? 8B 45 0C 89 04 24 E8 ? ? ? ? 25 ? ? ? ? 89 43 34"),
                ("IsPlayerOnFriends 32bit","55 89 E5 56 53 81 EC ? ? ? ? 65 A1 ? ? ? ? 89 45 F4 31 C0 8B 5D 0C E8"),
                ("IsPlayerOnFriends 64bit","55 48 89 E5 56 53 48 81 EC ? ? ? ? 65 48 ? ? ? ? ? ? 31 C0")]:
    r = scan(cl, pat)
    print("\n[%s] %d matches" % (lbl, len(r)))
    for m in r[:4]: print("  0x%x: %s" % (m, hd(cl, m, 56)))

print("\n=== String searches ===")
for name,data in [("engine",en),("client",cl)]:
    for s in [b"CL_Move",b"bSendPacket",b"SetPredictionRandomSeed",b"MD5_PseudoRandom",b"IsPlayerOnSteamFriendsList"]:
        pos = [m.start() for m in re.finditer(s, data)]
        if pos: print("  %s: '%s' at %s" % (name, s.decode(), [hex(x) for x in pos[:5]]))
