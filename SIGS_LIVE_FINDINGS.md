# TF2 64-bit — LIVE gdb inspection findings (PID 30389, bases: engine 0x71fb37c00000, client 0x71fb08200000, vguimatsurface 0x71fb35400000)

Runtime = base + file_offset (objdump/file address). Verified live via gdb attach
+ /proc/PID/mem reads.

## CONFIRMED live

- CPrediction (VClientPrediction001): obj 0x71fb0b0d10a0, vmt 0x71fb0acf3198.
  **CPrediction::RunCommand = vtable[19] = runtime 0x71fb09efb3d0 = client.so
  file offset 0x16fb3d0.** (sdk.h VMT_IPrediction: RunCommand /* 19 */.)
  RunCommand E8-callees (file offsets): 0x16fb2b0 (x3), 0x16fb160 (x2),
  0x16fb400, 0x16fb070 (thunk), 0x13d62c0 (Error@plt). One of
  0x16fb160/0x16fb2b0/0x16fb400 is StartCommand -> calls SetPredictionRandomSeed.

- CInput: obj 0x71fb0b0c6f80, vmt 0x71fb0acd2140 (40 entries dumped).
  **CInput::GetUserCmd = vtable[8] = runtime 0x71fb098333b0 = client.so file
  offset 0x16333b0** — CONFIRMED (it computes `sequence % 90` via imul
  0x5a=MULTIPLAYER_BACKUP, exactly the cheat's h_GetUserCmd logic). So this
  object is CInput.
  Found via IN_ActivateMouse (BaseClient vtable[14]) which is a thunk:
  `lea rax,[rip->.got 0x2da70a8]; mov rdi,[rax]; jmp *0x90(rdi)` — i.e. the
  CInput* lives at client.so .got 0x2da70a8 (runtime 0x71fb0ada70a8).

- BaseClient (VClient017): obj 0x71fb0afe6760, vmt 0x71fb0a8e76b0 (44 entries).
  Indices (from sdk.h VMT_BaseClient): LevelInitPostEntity=6, LevelShutdown=7,
  HudProcessInput=10, HudUpdate=11, IN_ActivateMouse=14, FrameStageNotify=35,
  GetPlayerView=59.

- Engine globals read live (value @ file offset):
    0xa0f720 -> 0x71fb0afe6760   (= BaseClient obj; so 0xa0f720 = g_pClient/BaseClient*)
    0xa0f7c0 -> 0x71fb38534440   (engine-internal ptr; NOT obviously CClientState)
    0xc58090 -> 0x388c8c40018    (NOT a clean pointer; CL_RegisterResources'
                                  error string is about worldmodel/GetModel,
                                  so 0xc58090 is model-related, NOT g_pClientState)
    0xc5fba0 -> float (~4.4)     (a time/counter, not a bool)
    0xc57f18/0xc57f1c -> packed floats
    bool candidates 0xb18448,0xb18449,0xa6fec0,0xa6feb0 all read 0 (not "sending")

## Conclusions for the remaining 5 sigs

- bSendPacket: NOT a standalone global among the candidates (none reads as a
  send-bool=1 while the game runs). Likely a FIELD of CClientState
  (e.g. m_bSendPacket) -> needs the CClientState object first, then
  bSendPacket = c_clientstate + offset. The 32-bit `bSendPacket = pat+1`
  (absolute imm) does not apply to 64-bit PIE.
- ClientState: the 0xc58090 candidate is WRONG (model-related). The real
  `cl`/g_pClientState must be found via a RIP-relative reference in CL_Move or
  CL_ReadPackets (decompilations in engine.so_anchors.txt). CClientState has
  m_NetChannel@0x10 and chokedcommands deep inside; use that to confirm.
- SetPredictionRandomSeed: home is StartCommand (a RunCommand callee). The old
  callsite byte-pattern does not match 64-bit. Disassemble 0x16fb160 /
  0x16fb2b0 / 0x16fb400 (the non-thunk RunCommand callees), find the call to
  SetPredictionRandomSeed; SetPredictionRandomSeed's body itself calls
  MD5_PseudoRandom, so finding one yields both.
- MD5_PseudoRandom: from CInput (obj+vmt above), find CInput::CreateMove
  (disassemble vtable entries around 8..30; CreateMove calls MD5_PseudoRandom
  with the command_number). Or get it from SetPredictionRandomSeed's body.
- IsPlayerOnSteamFriendsList: no string anchor; find via CTargetID
  (GetTargetForSteamAvatar). Hardest; may need GUI xref work.

## Recipe reminder
Once a target function address is known, build a UNIQUE entry-point signature
(wildcard RIP-relative disp + jmp/call rel32) like StartDrawing/FinishDrawing
(already done + builds), or a callsite sig with RELATIVE2ABSOLUTE(pat+N).
