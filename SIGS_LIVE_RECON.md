# Live gdb recon results (tf_linux64, PID at run time)

Recon script: /home/jms/Downloads/tf2_re/recon.gdb (+ recon_run.sh).
Output: /tmp/tf2_recon.txt. Module runtime bases (from /proc/PID/maps):
  engine.so 0x71fb37c00000   client.so 0x71fb08200000   vguimatsurface.so 0x71fb35400000
file_offset = runtime_addr - base. (Ghidra addrs = file_offset + 0x100000.)

## CONFIRMED (applied)
- StartDrawing  = vguimatsurface + 0x10e8f0  (entry sig, unique)
- FinishDrawing = vguimatsurface + 0x10e0f0  (entry sig, unique)
- ClientState 'cl' = engine + 0xa0f7c0 (the CClientState OBJECT in .bss; its +0 is a
  vtable ptr -> engine+0x934440). c_clientstate = &cl = RELATIVE2ABSOLUTE(pat+9)
  from the CL_ReadPackets callsite (unique sig in globals.h).

## Leads for the remaining 4 (from /tmp/tf2_recon.txt)
- CPrediction (VClientPrediction001) = client+0x2bd10a0; vmt @ client+0x2af3198.
  RunCommand = pred_vmt[18] = client+0x167eec0 (clean entry; 4 args rdi/rsi/rdx/rcx =
  IPrediction*/Entity*/usercmd*/MoveHelper*; matches sdk.h VMT_IPrediction RunCommand@18).
  RunCommand local callees: 0x167e390, 0x167e720, 0x167e990, 0x167ec60, 0x167e550,
  0x167ee10 (one is StartCommand -> SetPredictionRandomSeed; trace the E8 chain).
  SetPredictionRandomSeed: NOT found via `movl $-1,[rip]` scan (it likely writes through
  an int* global: `mov rax,[rip->ptr]; mov [rax],seed`). Find by disassembling the
  StartCommand callee and resolving its E8 call to a small set-global fn.
- BaseClient (VClient017) = client+0x2de760; vmt @ client+0x2ce76b0; vtable dumped
  0..63 in /tmp/tf2_recon.txt. engine global 0xa0f720 = g_pClient (holds BaseClient ptr).
  CInput (for MD5_PseudoRandom): get via BaseClient::vmt->IN_ActivateMouse (need its
  index in sdk.h VMT_BaseClient) -> its code lea's g_pInput -> CInput vtable ->
  CreateMove -> MD5_PseudoRandom. NOTE: the cheat's get_input()/get_clientmode()/
  get_globalvars() also use 32-bit byte_offsets (pat+1 etc.) and are BROKEN in 64-bit;
  they need the same RIP-relative rework as the signatures.
- bSendPacket: the 64-bit CL_Move send path is `bVar7 = FUN_004ef000(&cl);
  (*pcVar2)(time, g_pClient, count, bVar7 ^ 1)` — NO obvious standalone `bSendPacket`
  bool like the 32-bit sig. The 32-bit cheat's `*bSendPacket=false` choke may need a
  mechanism rethink against this path (e.g. hook the send call / netchannel). Engine
  bools seen: 0xa18448, 0xa18449 (both 0 at snapshot), 0xa18438/0xa18434 (counters).
- IsPlayerOnSteamFriendsList: CTargetID::GetTargetForSteamAvatar -> this fn; no string
  anchor. Hardest; needs CTargetID vtable RE or a breakpoint in CTargetID.

## To finish: re-run recon (TF2 running, sudo) to dump more vtables if needed:
  bash /home/jms/Downloads/tf2_re/recon_run.sh   # reads /tmp/tf2_recon.txt
