
#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h> /* PROT_* */
#include "include/math.h"
#include "include/globals.h"
#include "include/libsigscan.h"

/* SDL2 SwapWindow/PollEvent are hooked via their GOT entries in launcher.so
 * (R_X86_64_JUMP_SLOT relocations at these file offsets). The old 32-bit
 * approach used offsets in libSDL2 itself, but the game calls SDL via
 * launcher.so's GOT, which is writable. */
#define SWAPWINDOW_GOT_OFFSET 0x51458
#define POLLEVENT_GOT_OFFSET  0x511a8

#define GET_HANDLE(VAR, STR)                          \
    void* VAR = dlopen(STR, RTLD_LAZY | RTLD_NOLOAD); \
    if (!VAR) {                                       \
        ERR("Can't open " #VAR);                      \
        return false;                                 \
    }

#define GET_INTERFACE(HANDLE, VAR, STR) \
    VAR = get_interface(HANDLE, STR);   \
    if (!VAR || !VAR->vmt) {            \
        ERR("Can't load " #VAR);        \
        return false;                   \
    }

/* Check out this advanced regex conversion */
#define GET_SIGNATURE(VAR, MODULE, SIG)                \
    void* VAR = sigscan_module("^.*" MODULE "$", SIG); \
    if (!VAR) {                                        \
        ERR("Couldn't match signature for " #SIG);     \
        return false;                                  \
    }

/* Optional variant of GET_SIGNATURE: warn (don't abort) on miss, so the cheat
 * still loads with a reduced feature set if a signature isn't matched yet.
 * Call sites of the resolved pointer must NULL-check it. */
#define GET_SIGNATURE_OPT(VAR, MODULE, SIG)             \
    void* VAR = sigscan_module("^.*" MODULE "$", SIG);  \
    if (!VAR) {                                          \
        ERR("Couldn't match signature for " #SIG        \
            " (optional: feature disabled)");           \
    }

/*----------------------------------------------------------------------------*/

/* Global cache and fonts */
global_cache_t g;
font_list_t g_fonts;

/* Signature pointers */
bool* bSendPacket = NULL;

/* Signature functions */
StartDrawing_t StartDrawing                             = NULL;
FinishDrawing_t FinishDrawing                           = NULL;
SetPredictionRandomSeed_t SetPredictionRandomSeed       = NULL;
MD5_PseudoRandom_t MD5_PseudoRandom                     = NULL;
IsPlayerOnSteamFriendsList_t IsPlayerOnSteamFriendsList = NULL;

/* SDL functions */
SwapWindow_t* SwapWindowPtr = NULL;
PollEvent_t* PollEventPtr   = NULL;

/* Interfaces and classes
 * NOTE: Macro defined in globals.h */
DECL_INTF(BaseClient, baseclient);
DECL_INTF(EngineClient, engine);
DECL_INTF(EntityList, entitylist);
DECL_INTF(EngineVGui, enginevgui);
DECL_INTF(ICvar, cvar);
DECL_INTF(MatSurface, surface);
DECL_INTF(IPanel, panel);
DECL_INTF(IVModelInfo, modelinfo);
DECL_INTF(RenderView, renderview);
DECL_INTF(EngineTrace, enginetrace);
DECL_INTF(MaterialSystem, materialsystem);
DECL_INTF(ModelRender, modelrender);
DECL_INTF(GameMovement, gamemovement);
DECL_INTF(MoveHelper, movehelper);
DECL_INTF(IPrediction, prediction);
DECL_INTF(CInput, input);
DECL_INTF(ClientMode, clientmode);
DECL_CLASS(CClientState, clientstate);
DECL_CLASS(CGlobalVars, globalvars);

/*----------------------------------------------------------------------------*/

/* 64-bit: resolve the global singletons via signature-matched `lea r,[rip->GOT]`
 * callsites. RELATIVE2ABSOLUTE(pat+9) gives the GOT slot address; *(GOT slot) is
 * the object pointer. Confirmed at runtime (OverrideView vtable[17],
 * CGlobalVars layout, GetUserCmd vtable[8]). */
static inline ClientMode* get_clientmode(void) {
    GET_SIGNATURE(pat, CLIENT_SO, SIG_ClientMode);
    void** got = (void**)RELATIVE2ABSOLUTE(pat + 9);
    return *(ClientMode**)got;
}

static inline CGlobalVars* get_globalvars(void) {
    GET_SIGNATURE(pat, CLIENT_SO, SIG_GlobalVars);
    void** got = (void**)RELATIVE2ABSOLUTE(pat + 9);
    return *(CGlobalVars**)got;
}

static inline CInput* get_input(void) {
    GET_SIGNATURE(pat, CLIENT_SO, SIG_Input);
    void** got = (void**)RELATIVE2ABSOLUTE(pat + 9);
    return *(CInput**)got;
}

static inline bool get_sigs(void) {
    /* NOTE: Signature scanning and pointer functions can be a bit messy. Keep
     * in mind that RELATIVE2ABSOLUTE() dereferences the pointer once */

    /* MatSurface functions (64-bit: entry-point signatures -> match is the fn) */
    GET_SIGNATURE(pat_StartDrawing, MATSURFACE_SO, SIG_StartDrawing);
    StartDrawing = pat_StartDrawing;

    GET_SIGNATURE(pat_FinishDrawing, MATSURFACE_SO, SIG_FinishDrawing);
    FinishDrawing = pat_FinishDrawing;

    /* CL_Move's bSendPacket (optional: pSilent/anti-aim/fakelag).
     * 64-bit: bSendPacket is no longer a standalone global variable in 64-bit TF2.
     * To prevent crashes, we explicitly initialize it to NULL. Since all call sites
     * of bSendPacket are already NULL-guarded, this safely disables packet choking
     * features without compromising overall injection and cheat stability. */
    bSendPacket = NULL;

    /* ClientState (64-bit: 'cl' global object; resolve the lea->cl RIP target) */
    GET_SIGNATURE(pat_ClientState, ENGINE_SO, SIG_ClientState);
    c_clientstate = (CClientState*)RELATIVE2ABSOLUTE(pat_ClientState + 9);

    /* CBaseEntity::SetPredictionRandomSeed() (optional: prediction/meleebot) */
    GET_SIGNATURE_OPT(pat_SetPredictionRandomSeed, CLIENT_SO,
                      SIG_SetPredictionRandomSeed);
    if (pat_SetPredictionRandomSeed)
        SetPredictionRandomSeed =
          RELATIVE2ABSOLUTE(pat_SetPredictionRandomSeed + 19);

    /* MD5_PseudoRandom() (optional: prediction/meleebot) */
    GET_SIGNATURE_OPT(pat_MD5_PseudoRandom, CLIENT_SO, SIG_MD5_PseudoRandom);
    if (pat_MD5_PseudoRandom)
        MD5_PseudoRandom = RELATIVE2ABSOLUTE(pat_MD5_PseudoRandom + 18);

    /* IsPlayerOnSteamFriendsList() (optional: steam-friend ESP/aimbot filter).
     * NOTE: We don't use RELATIVE2ABSOLUTE() and we don't add any offset since
     * this is the signature to the function itself. */
    GET_SIGNATURE_OPT(pat_IsPlayerOnSteamFriendsList, CLIENT_SO,
                      SIG_IsPlayerOnSteamFriendsList);
    if (pat_IsPlayerOnSteamFriendsList)
        IsPlayerOnSteamFriendsList = pat_IsPlayerOnSteamFriendsList;

    return true;
}

/*----------------------------------------------------------------------------*/

bool globals_init(void) {
    /* Handles */
    GET_HANDLE(h_client, CLIENT_SO);
    GET_HANDLE(h_engine, ENGINE_SO);
    GET_HANDLE(h_matsurface, MATSURFACE_SO);
    GET_HANDLE(h_vgui, VGUI_SO);
    GET_HANDLE(h_materialsystem, MATERIALSYSTEM_SO);
    GET_HANDLE(h_vstdlib, VSTDLIB_SO);
    GET_HANDLE(h_sdl2, SDL_SO);

    /* SDL2: hook via GOT entries in launcher.so (writable, R_X86_64_JUMP_SLOT) */
    GET_HANDLE(h_launcher, "./bin/linux64/launcher.so");
    SwapWindowPtr = (SwapWindow_t*)GET_OFFSET(h_launcher, SWAPWINDOW_GOT_OFFSET);
    PollEventPtr  = (PollEvent_t*)GET_OFFSET(h_launcher, POLLEVENT_GOT_OFFSET);

    /* Interfaces */
    GET_INTERFACE(h_client, i_baseclient, "VClient017");
    GET_INTERFACE(h_engine, i_engine, "VEngineClient014");
    GET_INTERFACE(h_client, i_entitylist, "VClientEntityList003");
    GET_INTERFACE(h_engine, i_enginevgui, "VEngineVGui002");
    GET_INTERFACE(h_vstdlib, i_cvar, "VEngineCvar004");
    GET_INTERFACE(h_matsurface, i_surface, "VGUI_Surface030");
    GET_INTERFACE(h_vgui, i_panel, "VGUI_Panel009");
    GET_INTERFACE(h_engine, i_modelinfo, "VModelInfoClient006");
    GET_INTERFACE(h_engine, i_renderview, "VEngineRenderView014");
    GET_INTERFACE(h_engine, i_enginetrace, "EngineTraceClient003");
    GET_INTERFACE(h_materialsystem, i_materialsystem, "VMaterialSystem082");
    GET_INTERFACE(h_engine, i_modelrender, "VEngineModel016");
    GET_INTERFACE(h_client, i_gamemovement, "GameMovement001");
    GET_INTERFACE(h_client, i_prediction, "VClientPrediction001");

    /* Other interfaces */
    i_clientmode = get_clientmode();
    if (!i_clientmode || !i_clientmode->vmt) {
        ERR("Couldn't load i_clientmode");
        return false;
    }

    c_globalvars = get_globalvars();
    if (!c_globalvars) {
        ERR("Couldn't load c_globalvars");
        return false;
    }

    i_input = get_input();
    if (!i_input) {
        ERR("Couldn't load i_input");
        return false;
    }

    /* Needed for write permission on the VMTs. Macro declared in globals.h */
    CLONE_VMT(i_baseclient);
    CLONE_VMT(i_clientmode);
    CLONE_VMT(i_enginevgui);
    CLONE_VMT(i_panel);
    CLONE_VMT(i_modelrender);
    CLONE_VMT(i_prediction);
    CLONE_VMT(i_input);
    CLONE_VMT(i_surface);

    dlclose(h_client);
    dlclose(h_engine);
    dlclose(h_matsurface);
    dlclose(h_vgui);
    dlclose(h_materialsystem);
    dlclose(h_sdl2);

    /* Individual functions/globals from signatures */
    if (!get_sigs())
        return false;

    /* Initialize global cache */
    cache_reset();
    cache_reset_cvars();
    cache_update();
    if (g.IsInGame) {
        /* Call stuff that should be run each level change when injecting */
        g.localidx = METHOD(i_engine, GetLocalPlayer);
        cache_get_model_idx();
    }

    return true;
}

bool resore_vtables(void) {
    /* Restore original VTables when unloading. Macro declared in globals.h */
    RESTORE_VMT(i_baseclient);
    RESTORE_VMT(i_clientmode);
    RESTORE_VMT(i_enginevgui);
    RESTORE_VMT(i_panel);
    RESTORE_VMT(i_modelrender);
    RESTORE_VMT(i_prediction);
    RESTORE_VMT(i_input);
    RESTORE_VMT(i_surface);

    return true;
}

/*----------------------------------------------------------------------------*/

#define CREATE_FONT(FONT)                                                 \
    if (!METHOD_ARGS(i_surface, SetFontGlyphSet, FONT.id, FONT.name,      \
                     FONT.tall, FONT.weight, 0, 0, FONT.flags, 0, 0)) {   \
        fprintf(stderr,                                                   \
                "WARNING: fonts_init: couldn't create font \"%s\" using " \
                "default monospace.\n",                                   \
                FONT.name);                                               \
        FONT.id = 16;                                                     \
    }

void fonts_init(void) {
    /* Initialize font_t structs */
    g_fonts.main = (font_t){
        .name   = "CozetteVector",
        .tall   = 15,
        .weight = 700,
        .flags  = FONTFLAG_DROPSHADOW | FONTFLAG_ANTIALIAS,
        .id     = METHOD(i_surface, CreateFont),
    };
    g_fonts.small = (font_t){
        .name   = "CozetteVector",
        .tall   = 14,
        .weight = 700,
        .flags  = FONTFLAG_DROPSHADOW | FONTFLAG_ANTIALIAS,
        .id     = METHOD(i_surface, CreateFont),
    };
    g_fonts.tiny = (font_t){
        .name   = "CozetteVector",
        .tall   = 13, /* Digits are a bit weird */
        .weight = 700,
        .flags  = FONTFLAG_DROPSHADOW | FONTFLAG_ANTIALIAS,
        .id     = METHOD(i_surface, CreateFont),
    };

    /* Create fonts with the data */
    CREATE_FONT(g_fonts.main);
    CREATE_FONT(g_fonts.small);
    CREATE_FONT(g_fonts.tiny);
}

/*----------------------------------------------------------------------------*/

#define STORE_MDL(arr_idx, mdl_str) \
    g.mdl_idx[MDLIDX_##arr_idx] =   \
      METHOD_ARGS(i_modelinfo, GetModelIndex, mdl_str);

/* Will be called once per level change in LevelInitPostEntity */
void cache_get_model_idx(void) {
    /* Health */
    STORE_MDL(MEDKIT_SMALL, "models/items/medkit_small.mdl");
    STORE_MDL(MEDKIT_MEDIUM, "models/items/medkit_medium.mdl");
    STORE_MDL(MEDKIT_LARGE, "models/items/medkit_large.mdl");
    STORE_MDL(MEDKIT_SMALL_BDAY, "models/items/medkit_small_bday.mdl");
    STORE_MDL(MEDKIT_MEDIUM_BDAY, "models/items/medkit_medium_bday.mdl");
    STORE_MDL(MEDKIT_LARGE_BDAY, "models/items/medkit_large_bday.mdl");
    STORE_MDL(PLATE, "models/items/plate.mdl");
    STORE_MDL(PLATE_STEAK, "models/items/plate_steak.mdl");
    STORE_MDL(HALLOWEEN_MEDKIT_SMALL, "models/props_halloween/"
                                      "halloween_medkit_small.mdl");
    STORE_MDL(HALLOWEEN_MEDKIT_MEDIUM, "models/props_halloween/"
                                       "halloween_medkit_medium.mdl");
    STORE_MDL(HALLOWEEN_MEDKIT_LARGE, "models/props_halloween/"
                                      "halloween_medkit_large.mdl");
    STORE_MDL(MUSHROOM_LARGE, "models/items/ld1/mushroom_large.mdl");

    /* Ammo */
    STORE_MDL(AMMOPACK_SMALL, "models/items/ammopack_small.mdl");
    STORE_MDL(AMMOPACK_MEDIUM, "models/items/ammopack_medium.mdl");
    STORE_MDL(AMMOPACK_LARGE, "models/items/ammopack_large.mdl");
    STORE_MDL(AMMOPACK_LARGE_BDAY, "models/items/ammopack_large_bday.mdl");
    STORE_MDL(AMMOPACK_MEDIUM_BDAY, "models/items/ammopack_medium_bday.mdl");
    STORE_MDL(AMMOPACK_SMALL_BDAY, "models/items/ammopack_small_bday.mdl");
}

#define GET_CONVAR_FLT(NAME)                        \
    static ConVar* NAME = NULL;                     \
    if (!NAME) {                                    \
        NAME = METHOD_ARGS(i_cvar, FindVar, #NAME); \
    }                                               \
    g.NAME = ConVar_GetFloat(NAME);

void cache_store_cvars(void) {
    /* ConVar pointers, used to get the values */
    GET_CONVAR_FLT(sv_airaccelerate);
    GET_CONVAR_FLT(sv_maxspeed);
    GET_CONVAR_FLT(cl_forwardspeed);
    GET_CONVAR_FLT(cl_sidespeed);
}

void cache_reset_cvars(void) {
    g.sv_airaccelerate = 10.0f;
    g.sv_maxspeed      = 320.0f;
    g.cl_forwardspeed  = 450.0f;
    g.cl_sidespeed     = 450.0f;
}

/* Will be called each frame in FRAME_NET_UPDATE_START */
void cache_reset(void) {
    g.IsInGame    = false;
    g.IsConnected = false;
    g.IsAlive     = false;
    g.MaxClients  = 0;
    g.MaxEntities = 0;

    g.localplayer = NULL;
    g.localweapon = NULL;
    for (int i = 0; i < (int)LENGTH(g.ents); i++)
        g.ents[i] = NULL;
}

/* Will be called each frame in FRAME_NET_UPDATE_END */
void cache_update(void) {
    g.IsInGame    = METHOD(i_engine, IsInGame);
    g.IsConnected = METHOD(i_engine, IsConnected);

    if (g.IsInGame) {
        g.MaxClients  = METHOD(i_engine, GetMaxClients);
        g.MaxEntities = METHOD(i_entitylist, GetMaxEntities);

        /* Store localplayer even if not alive */
        g.localplayer = METHOD_ARGS(i_entitylist, GetClientEntity, g.localidx);
        if (g.localplayer) {
            g.IsAlive = METHOD(g.localplayer, IsAlive);

            if (g.IsAlive)
                g.localweapon = METHOD(g.localplayer, GetWeapon);
        }

        /* First iterate players */
        for (int i = 1; i <= g.MaxClients; i++) {
            Entity* ent      = METHOD_ARGS(i_entitylist, GetClientEntity, i);
            Networkable* net = GetNetworkable(ent);

            if (!ent || METHOD(net, IsDormant) || !METHOD(ent, IsAlive))
                continue;

            g.ents[i] = ent;
        }

        /* Then other entities */
        const int last_entity = MIN(MAX_ENTITIES, g.MaxEntities);
        for (int i = g.MaxClients + 1; i < last_entity; i++) {
            Entity* ent      = METHOD_ARGS(i_entitylist, GetClientEntity, i);
            Networkable* net = GetNetworkable(ent);

            if (!ent || METHOD(net, IsDormant))
                continue;

            g.ents[i] = ent;
        }
    }
}
