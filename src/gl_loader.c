/*
 * gl_loader.c - Container-friendly GL loader replacing the libGLEW dependency.
 *
 * TF2 runs inside Steam's pressure-vessel container, whose /usr/lib does NOT
 * contain libGLEW.so. The cheat only used GLEW for the ~28 GL extension
 * function pointers that nuklear_sdl_gl3 needs. Instead of linking libGLEW
 * (which then fails to load inside the container), we define those __glew*
 * pointer globals here and fill them at runtime with SDL_GL_GetProcAddress,
 * which the game already uses and which resolves against the container's GL.
 *
 * <GL/glew.h> (still included by menu.c) `#define`s e.g.
 *     glActiveTexture -> GLEW_GET_FUN(__glewActiveTexture) -> __glewActiveTexture
 * so a call `glActiveTexture(t)` becomes `__glewActiveTexture(t)`, i.e. calling
 * the function pointer we own here. We just have to provide and populate it.
 *
 * The Makefile no longer links -lGLEW; this translation unit supplies every
 * symbol that used to come from it (the 28 __glew* pointers, glewInit,
 * glewGetErrorString).
 */
#include <GL/glew.h>
#include <SDL2/SDL.h>

/* ---- The GL extension function pointers nuklear_sdl_gl3 uses ---- */
PFNGLACTIVETEXTUREPROC            __glewActiveTexture            = NULL;
PFNGLATTACHSHADERPROC             __glewAttachShader             = NULL;
PFNGLBINDBUFFERPROC               __glewBindBuffer               = NULL;
PFNGLBINDVERTEXARRAYPROC          __glewBindVertexArray          = NULL;
PFNGLBLENDEQUATIONPROC            __glewBlendEquation            = NULL;
PFNGLBUFFERDATAPROC               __glewBufferData               = NULL;
PFNGLCOMPILESHADERPROC            __glewCompileShader            = NULL;
PFNGLCREATEPROGRAMPROC            __glewCreateProgram            = NULL;
PFNGLCREATESHADERPROC             __glewCreateShader            = NULL;
PFNGLDELETEBUFFERSPROC            __glewDeleteBuffers            = NULL;
PFNGLDELETEPROGRAMPROC            __glewDeleteProgram            = NULL;
PFNGLDELETESHADERPROC             __glewDeleteShader             = NULL;
PFNGLDETACHSHADERPROC             __glewDetachShader             = NULL;
PFNGLENABLEVERTEXATTRIBARRAYPROC  __glewEnableVertexAttribArray  = NULL;
PFNGLGENBUFFERSPROC               __glewGenBuffers               = NULL;
PFNGLGENVERTEXARRAYSPROC          __glewGenVertexArrays          = NULL;
PFNGLGETATTRIBLOCATIONPROC        __glewGetAttribLocation        = NULL;
PFNGLGETPROGRAMIVPROC             __glewGetProgramiv             = NULL;
PFNGLGETSHADERIVPROC              __glewGetShaderiv              = NULL;
PFNGLGETUNIFORMLOCATIONPROC       __glewGetUniformLocation       = NULL;
PFNGLLINKPROGRAMPROC              __glewLinkProgram              = NULL;
PFNGLMAPBUFFERPROC                __glewMapBuffer                = NULL;
PFNGLSHADERSOURCEPROC             __glewShaderSource             = NULL;
PFNGLUNIFORM1IPROC                __glewUniform1i                = NULL;
PFNGLUNIFORMMATRIX4FVPROC         __glewUniformMatrix4fv         = NULL;
PFNGLUNMAPBUFFERPROC              __glewUnmapBuffer              = NULL;
PFNGLUSEPROGRAMPROC               __glewUseProgram              = NULL;
PFNGLVERTEXATTRIBPOINTERPROC      __glewVertexAttribPointer      = NULL;

/* Replacement for GLEW's glewInit(). Must be called after a GL context is
 * current (menu.c calls it right after SDL_GL_CreateContext, as before).
 * Returns GLEW_OK (0) on success. Each GL extension pointer is resolved via
 * SDL_GL_GetProcAddress, which works inside Steam's pressure-vessel container
 * (unlike libGLEW, which isn't present there). */
GLenum glewInit(void) {
    __glewActiveTexture           = (PFNGLACTIVETEXTUREPROC)SDL_GL_GetProcAddress("glActiveTexture");
    __glewAttachShader            = (PFNGLATTACHSHADERPROC)SDL_GL_GetProcAddress("glAttachShader");
    __glewBindBuffer              = (PFNGLBINDBUFFERPROC)SDL_GL_GetProcAddress("glBindBuffer");
    __glewBindVertexArray         = (PFNGLBINDVERTEXARRAYPROC)SDL_GL_GetProcAddress("glBindVertexArray");
    __glewBlendEquation           = (PFNGLBLENDEQUATIONPROC)SDL_GL_GetProcAddress("glBlendEquation");
    __glewBufferData              = (PFNGLBUFFERDATAPROC)SDL_GL_GetProcAddress("glBufferData");
    __glewCompileShader           = (PFNGLCOMPILESHADERPROC)SDL_GL_GetProcAddress("glCompileShader");
    __glewCreateProgram           = (PFNGLCREATEPROGRAMPROC)SDL_GL_GetProcAddress("glCreateProgram");
    __glewCreateShader            = (PFNGLCREATESHADERPROC)SDL_GL_GetProcAddress("glCreateShader");
    __glewDeleteBuffers           = (PFNGLDELETEBUFFERSPROC)SDL_GL_GetProcAddress("glDeleteBuffers");
    __glewDeleteProgram           = (PFNGLDELETEPROGRAMPROC)SDL_GL_GetProcAddress("glDeleteProgram");
    __glewDeleteShader            = (PFNGLDELETESHADERPROC)SDL_GL_GetProcAddress("glDeleteShader");
    __glewDetachShader            = (PFNGLDETACHSHADERPROC)SDL_GL_GetProcAddress("glDetachShader");
    __glewEnableVertexAttribArray  = (PFNGLENABLEVERTEXATTRIBARRAYPROC)SDL_GL_GetProcAddress("glEnableVertexAttribArray");
    __glewGenBuffers              = (PFNGLGENBUFFERSPROC)SDL_GL_GetProcAddress("glGenBuffers");
    __glewGenVertexArrays         = (PFNGLGENVERTEXARRAYSPROC)SDL_GL_GetProcAddress("glGenVertexArrays");
    __glewGetAttribLocation       = (PFNGLGETATTRIBLOCATIONPROC)SDL_GL_GetProcAddress("glGetAttribLocation");
    __glewGetProgramiv            = (PFNGLGETPROGRAMIVPROC)SDL_GL_GetProcAddress("glGetProgramiv");
    __glewGetShaderiv             = (PFNGLGETSHADERIVPROC)SDL_GL_GetProcAddress("glGetShaderiv");
    __glewGetUniformLocation      = (PFNGLGETUNIFORMLOCATIONPROC)SDL_GL_GetProcAddress("glGetUniformLocation");
    __glewLinkProgram             = (PFNGLLINKPROGRAMPROC)SDL_GL_GetProcAddress("glLinkProgram");
    __glewMapBuffer               = (PFNGLMAPBUFFERPROC)SDL_GL_GetProcAddress("glMapBuffer");
    __glewShaderSource            = (PFNGLSHADERSOURCEPROC)SDL_GL_GetProcAddress("glShaderSource");
    __glewUniform1i               = (PFNGLUNIFORM1IPROC)SDL_GL_GetProcAddress("glUniform1i");
    __glewUniformMatrix4fv        = (PFNGLUNIFORMMATRIX4FVPROC)SDL_GL_GetProcAddress("glUniformMatrix4fv");
    __glewUnmapBuffer             = (PFNGLUNMAPBUFFERPROC)SDL_GL_GetProcAddress("glUnmapBuffer");
    __glewUseProgram              = (PFNGLUSEPROGRAMPROC)SDL_GL_GetProcAddress("glUseProgram");
    __glewVertexAttribPointer     = (PFNGLVERTEXATTRIBPOINTERPROC)SDL_GL_GetProcAddress("glVertexAttribPointer");
    return GLEW_OK;
}

/* Replacement for GLEW's glewGetErrorString(). The cheat only uses it to print
 * the glewInit() error, which never happens now (we always return GLEW_OK). */
const GLubyte* glewGetErrorString(GLenum error) {
    static const GLubyte msg[] = "no error (custom gl loader)";
    (void)error;
    return msg;
}