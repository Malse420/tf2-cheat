# TF2 64-bit signature port — status

Tracks the 32-bit → 64-bit signature/offset port of the Enoch cheat, driven by
Ghidra analysis of the 64-bit TF2 Linux binaries.

The 64-bit game code is split across these shared libraries (no single
`tf2_linux64` ELF exists; `tf_linux64` is only a 16 KB launcher):

    bin/linux64/engine.so          (11 MB)   bSendPacket, ClientState
    bin/linux64/vguimatsurface.so  (3 MB)    StartDrawing, FinishDrawing
    tf/bin/linux64/client.so       (46 MB)   SetPredictionRandomSeed,
                                             MD5_PseudoRandom,
                                             IsPlayerOnSteamFriendsList

NOTE: Ghidra imported these ELFs with image base 0x100000, so a Ghidra address
`0x00xxxxxx` maps to the file/objdump address `0x00xxxxxx - 0x100000`. File
addresses are what the cheat's matches resolve to at runtime.

## Ghidra project & artifacts (open in the GUI to finish the remaining sigs)

- Project: /home/jms/Downloads/tf2_re/projects/TF2L64c.gpr
  Open:   /home/jms/Downloads/ghidra_12.1.2_PUBLIC_20260605/ghidra_12.1.2_PUBLIC/ghidraRun
  Contains: engine.so, client.so (analyzed). vguimatsurface.so was solved via
  objdump (re-import if you want it in the GUI).
- Exported by DumpTF2.java (headless) in /home/jms/Downloads/tf2_re/out/:
    engine.so_anchors.txt   decompiled CL_Move/CL_ReadPackets/CL_RegisterResources
    engine.so_functions.csv all 19566 functions (addr,name,size)
    engine.so_strings.txt   all defined strings
    client.so_*             same set (anchors empty for the 3 target fns — they
                            have no string anchors; use the vtable approach)
- Helper scripts in /home/jms/Downloads/tf2_re/:
    launch_ghidra_c.sh, scripts/DumpTF2.java,
    scan_subpatterns.py, find_finishdrawing.py, find_bsendpacket.py,
    find_clmove_bools.py, check_uniq.py

## DONE — signatures updated & verified (builds cleanly)

Both switched to robust entry-point signatures (match == the function; no
RELATIVE2ABSOLUTE offset). Each verified UNIQUE in vguimatsurface.so.

| Sig              | Module            | Function addr (file) | Status |
|-------------------|-------------------|----------------------|--------|
| SIG_StartDrawing  | vguimatsurface.so | 0x10e8f0             | DONE   |
| SIG_FinishDrawing | vguimatsurface.so | 0x10e0f0             | DONE   |
| SIG_ClientState   | engine.so         | 0xa0f7c0 (cl object) | DONE   |

## OPTIONAL sigs — cheat now LOADS without them (feature-specific)

The 4 below use the new `GET_SIGNATURE_OPT` macro (warns, doesn't abort) and all
their call sites are NULL-guarded. The cheat loads & runs with ESP, aimbot, menu,
movement, visuals, chams, etc. Each sig, once finished, re-enables its feature.

| Sig                          | Feature it powers               | Status     |
|------------------------------|---------------------------------|------------|
| SIG_bSendPacket              | pSilent / anti-aim / fakelag     | TODO (live)|
| SIG_SetPredictionRandomSeed  | engine prediction + meleebot    | TODO (live)|
| SIG_MD5_PseudoRandom         | engine prediction + meleebot    | TODO (live)|
| SIG_IsPlayerOnSteamFriendsList| steam-friend ESP/aimbot filter  | TODO (live)|

Mechanism: `GET_SIGNATURE_OPT` in globals.c; NULL-guards in hooks.c, antiaim.c,
prediction.c, meleebot.c, and the IsSteamFriend macro in sdk/entity.h.

globals.c: `StartDrawing = pat_StartDrawing;` / `FinishDrawing = pat_FinishDrawing;`
(was RELATIVE2ABSOLUTE(pat+N)). `make` builds libenoch.so cleanly.

## VERIFIED — already correct for 64-bit (no change needed)

- Interface version strings all present in their 64-bit binaries: VClient017,
  VEngineClient014, VClientEntityList003, VEngineVGui002, VEngineCvar004,
  VGUI_Surface030, VGUI_Panel009, VModelInfoClient006, VEngineRenderView014,
  EngineTraceClient003, VMaterialSystem082, VEngineModel016, GameMovement001,
  VClientPrediction001. (VMaterialSystem082 already fixed by a prior edit.)
- SDL2 offsets SWAPWINDOW_OFFSET 0x53C00 / POLLEVENT_OFFSET 0x4B180 already
  match the system 64-bit libSDL2-2.0.so.0 (SDL_GL_SwapWindow@0x53c00,
  SDL_PollEvent@0x4b180). Long-term: dlsym these (SDL2 exports them) for
  robustness across SDL builds.


## REMAINING — finalize in Ghidra GUI (or via exported CSVs)

The old 32-bit sigs below DO NOT match 64-bit (verified 0 hits). Until replaced,
`globals_init()` aborts at the first failing `GET_SIGNATURE` (cheat self-unloads).
Replace each with a 64-bit pattern resolving to the confirmed target.

### bSendPacket (engine.so) — bool* the cheat writes to choke packets
- Home: CL_Move = objdump 0x3b44b0 / Ghidra FUN_004b44b0. Full decompilation in
  engine.so_anchors.txt (ANCHOR: CL_Move).
- Cheat semantics: `*bSendPacket = false` (choke) / `= true` (send); also
  `if (*bSendPacket)`. Must point to the global bool the engine checks before send.
- Candidates referenced in CL_Move (file addrs):
    0xa0f7c0 (DAT_00b0f7c0) passed by & to FUN_004ef000/004ef270/004acf60
    0xa0f720 (DAT_00b0f720) net-channel-like ptr (*+0xa8 called to send)
    0xc58090 (DAT_00d58090) set in CL_RegisterResources
  The explicit `bSendPacket = 1` write isn't obvious in the decompilation. In
  the GUI, open FUN_004b44b0 and find the byte tested right before the send call
  `(*pcVar2)(DAT_00d580a0 - param_1, ...)`.
- 64-bit handling: replace `bSendPacket = pat_bSendPacket + 1;` (32-bit absolute
  imm) with `bSendPacket = RELATIVE2ABSOLUTE(pat_bSendPacket + N);` where N is the
  offset of the RIP-relative disp referencing the bool. Keep
  protect_addr(bSendPacket, PROT_READ|PROT_WRITE) (drop EXEC).

### ClientState / c_clientstate (engine.so) — CClientState* (reads .chokedcommands)
- Home: CL_RegisterResources = 0x3b39a0 / FUN_004b39a0; also CL_ReadPackets =
  0x3b2e40 / FUN_004b2e40 (see anchors file).
- Decompilation: `FUN_00622240(&DAT_00d58090, uVar1); if (DAT_00d58090 == 0)` ->
  0xc58090 is a pointer global initialized here (strong g_pClientState candidate).
  The recurring &0xa0f7c0 may be the `cl` CClientState object.
- Cheat needs c_clientstate = the CClientState OBJECT pointer. Confirm in GUI
  whether it's 0xa0f7c0 (lea to object) or *(0xc58090) (deref g_pClientState).
- 64-bit handling: `c_clientstate = *(CClientState**)(pat + 3)` becomes either
  `c_clientstate = (CClientState*)RELATIVE2ABSOLUTE(pat+N)` or
  `c_clientstate = *(CClientState**)RELATIVE2ABSOLUTE(pat+N)` per confirmation.

### SetPredictionRandomSeed, MD5_PseudoRandom, IsPlayerOnSteamFriendsList (client.so)
- No string anchors (DumpTF2 found none). Use the vtable approach:
    * CPrediction (VClientPrediction001): vtable RunCommand is index 19
      (VMT_IPrediction in src/include/sdk.h). RunCommand -> StartCommand ->
      SetPredictionRandomSeed.
    * CInput: via get_input() (IN_ActivateMouse). CreateMove calls MD5_PseudoRandom.
      GetUserCmd is vtable index 8 (VMT_CInput).
    * CTargetID::GetTargetForSteamAvatar -> IsPlayerOnSteamFriendsList.
  Find the InterfaceReg linked list for VClientPrediction001 (string in
  client.so_strings.txt), walk to the factory, index the vtable.
- Once each function address is known, build an entry-point signature (like
  StartDrawing/FinishDrawing) and set the pointer directly — removes the fragile
  RELATIVE2ABSOLUTE(pat+N) offsets currently in globals.c.

## Recipe used for StartDrawing/FinishDrawing (apply to the remaining five)

1. Find the function in Ghidra (here via the draw-flag global: StartDrawing sets
   byte@0x3075b0 = 1; FinishDrawing sets it = 0).
2. Copy entry bytes from `objdump -d`, wildcard every RIP-relative displacement
   and jmp/call rel32 as `?`.
3. Verify UNIQUE with check_uniq.py (exactly one hit).
4. Set the global to the match directly (entry sig) in globals.c.
