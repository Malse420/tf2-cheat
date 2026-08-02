# Ghidra headless script to find function signatures and offsets in 64-bit TF2 binaries
# @category TF2
# @runtime Jython

from ghidra.program.model.symbol import SymbolType


def get_function_bytes(func, max_bytes=64):
    """Get the first N bytes of a function as hex string."""
    addr = func.getEntryPoint()
    result = []
    for i in range(max_bytes):
        try:
            b = getByte(addr.add(i)) & 0xFF
            result.append("%02X" % b)
        except:
            break
    return " ".join(result)


def find_function_by_name(name_pattern):
    """Find functions by name pattern."""
    results = []
    symTable = currentProgram.getSymbolTable()
    for sym in symTable.getAllSymbols(True):
        if sym.getSymbolType() == SymbolType.FUNCTION:
            name = sym.getName()
            if name_pattern.lower() in name.lower():
                func = getFunctionAt(sym.getAddress())
                if func:
                    results.append((name, func))
    return results


def get_ida_pattern(func, length=30):
    """Get first N bytes as IDA-style pattern."""
    addr = func.getEntryPoint()
    result = []
    for i in range(length):
        try:
            b = getByte(addr.add(i)) & 0xFF
            result.append("%02X" % b)
        except:
            result.append("??")
    return " ".join(result)


# ============================================================
print("=" * 70)
print("Ghidra Signature Finder for TF2 64-bit")
print("=" * 70)

# Search for key functions
search_names = [
    "StartDrawing",
    "FinishDrawing",
    "StartDrawing_",
    "FinishDrawing_",
    "CL_Move",
    "bSendPacket",
    "SetPredictionRandomSeed",
    "MD5_PseudoRandom",
    "IsPlayerOnSteamFriendsList",
    "HudProcessInput",
    "HudUpdate",
    "IN_ActivateMouse",
    "GetClientMode",
    "g_pClientMode",
    "gpGlobals",
]

for name in search_names:
    funcs = find_function_by_name(name)
    if funcs:
        for fname, func in funcs:
            print("\nFunction: %s" % fname)
            print("  Address: %s" % func.getEntryPoint())
            print("  Bytes: %s" % get_function_bytes(func, 40))
            print("  IDA Pattern: %s" % get_ida_pattern(func, 30))
    else:
        print("\nNot found: %s" % name)

# Also search for all symbols containing "Draw" or "Paint"
print("\n" + "=" * 70)
print("All symbols containing 'Draw' or 'Paint':")
print("=" * 70)
symTable = currentProgram.getSymbolTable()
count = 0
for sym in symTable.getAllSymbols(True):
    name = sym.getName()
    if ("draw" in name.lower() or "paint" in name.lower()) and count < 50:
        print("  %s at %s (type: %s)" % (name, sym.getAddress(), sym.getSymbolType()))
        count += 1

# Search for global variables that might be bSendPacket, g_pClientMode, etc.
print("\n" + "=" * 70)
print("Global variables of interest:")
print("=" * 70)
for sym in symTable.getAllSymbols(True):
    name = sym.getName()
    if (
        sym.getSymbolType() == SymbolType.LABEL
        or sym.getSymbolType() == SymbolType.DATA
    ):
        if any(
            x in name.lower()
            for x in ["sendpacket", "clientmode", "globals", "clientstate", "cl_move"]
        ):
            print(
                "  %s at %s (type: %s)" % (name, sym.getAddress(), sym.getSymbolType())
            )

print("\n" + "=" * 70)
print("Done!")
print("=" * 70)
