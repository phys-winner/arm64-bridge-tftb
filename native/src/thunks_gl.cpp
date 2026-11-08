#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "game_port_config.h"
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <GLES/gl.h>
#include <GLES/glext.h>
#include <android/log.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>


// Mirror of the current buffer bindings. Querying the driver with glGetIntegerv inside
// glDrawElements/glVertexAttribPointer cost a round-trip on every draw call.
static GLuint s_bound_array_buffer = 0;
static GLuint s_bound_element_buffer = 0;
static GLuint s_bound_framebuffer = 0;

struct GuestMappedBuffer {
    uint32_t address = 0;
    GLsizeiptr size = 0;
};
static std::unordered_map<GLenum, GuestMappedBuffer> s_mapped_buffers;
static std::mutex s_mapped_buffers_mutex;

// UI scaling, the virtual-resolution way: tell the guest the screen is
// s_virtual{Width,Height} and stretch the result here. The guest sizes its viewport
// in those units while the real default framebuffer is still the surface size, so
// the window-system framebuffer -- and only that one -- gets mapped back. Offscreen
// targets are allocated in the guest's own units and must not be touched, which is
// what the s_bound_framebuffer check is for.
// Leave s_virtualWidth/Height at 0 to disable the whole path.
static void ScaleViewportToSurface(GLint& x, GLint& y, GLsizei& w, GLsizei& h) {
    if (s_bound_framebuffer != 0) return;
    const uint32_t vw = ThunkManager::s_virtualWidth, vh = ThunkManager::s_virtualHeight;
    const uint32_t rw = ThunkManager::s_screenWidth, rh = ThunkManager::s_screenHeight;
    if (!vw || !vh || !rw || !rh || (vw == rw && vh == rh)) return;
    x = static_cast<GLint>((float)x * rw / vw);
    w = static_cast<GLsizei>((float)w * rw / vw);
    y = static_cast<GLint>((float)y * rh / vh);
    h = static_cast<GLsizei>((float)h * rh / vh);
}
#define LOG_TAG "Arm32Bridge_GL"
#if ARM32_BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

#if ARM32_BRIDGE_ENABLE_LOGGING
static uint32_t g_draw_calls = 0;
static uint32_t g_clear_calls = 0;
#endif

namespace {

constexpr GLsizei kDirectionalLightShadowHighSourceLength = 1797;
constexpr uint64_t kDirectionalLightShadowHighFnv1a64 = 0x8C8CF6E73DC808E8ULL;

uint64_t Fnv1a64(const std::string& value) {
    uint64_t hash = 14695981039346656037ULL;
    for (const char byte : value) {
        hash ^= static_cast<unsigned char>(byte);
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool HasGlExtension(const char* extensions, const char* extension) {
    if (!extensions || !extension || !*extension || strchr(extension, ' ')) return false;

    const size_t extension_length = strlen(extension);
    for (const char* match = strstr(extensions, extension); match;
         match = strstr(match + extension_length, extension)) {
        const bool starts_token = match == extensions || match[-1] == ' ';
        const char after = match[extension_length];
        if (starts_token && (after == '\0' || after == ' ')) return true;
    }
    return false;
}

bool ReadShaderSource(GLuint shader, std::string& source) {
    GLint source_length = 0;
    glGetShaderiv(shader, GL_SHADER_SOURCE_LENGTH, &source_length);
    if (source_length <= 1 || source_length > 64 * 1024) return false;

    std::vector<GLchar> buffer(static_cast<size_t>(source_length));
    GLsizei written = 0;
    glGetShaderSource(shader, source_length, &written, buffer.data());
    if (written <= 0 || written >= source_length) return false;
    source.assign(buffer.data(), static_cast<size_t>(written));
    return true;
}

bool ReplaceExactlyOnce(std::string& source, const char* from, const char* to) {
    const size_t from_length = strlen(from);
    const size_t position = source.find(from);
    if (position == std::string::npos ||
        source.find(from, position + from_length) != std::string::npos) {
        return false;
    }
    source.replace(position, from_length, to);
    return true;
}

bool RewriteDirectionalLightShadowHigh(const std::string& source, std::string& rewritten) {
    if (source.size() != kDirectionalLightShadowHighSourceLength ||
        Fnv1a64(source) != kDirectionalLightShadowHighFnv1a64) {
        return false;
    }

    rewritten = source;
    if (!ReplaceExactlyOnce(rewritten,
                            "#extension GL_EXT_shadow_samplers:require\n",
                            "// ARM64 bridge: emulate the unavailable shadow sampler\n") ||
        !ReplaceExactlyOnce(rewritten,
                            "#define ttShadow2D shadow2DEXT\n",
                            "#define ttShadow2D(s,c) step(clamp((c).z,0.0,1.0),texture2D(s,(c).xy).r)\n") ||
        !ReplaceExactlyOnce(rewritten,
                            "ulow sampler2DShadow SA;\n",
                            "ulow sampler2D SA;\n")) {
        return false;
    }

    return rewritten.find("GL_EXT_shadow_samplers") == std::string::npos &&
           rewritten.find("sampler2DShadow") == std::string::npos &&
           rewritten.find("shadow2DEXT") == std::string::npos;
}

}  // namespace

void RegisterGles2CoreThunks(ThunkManager& manager);
size_t GetGlStateValueCount(GLenum pname);

void ThunkManager::RegisterGLThunks() {
    uint8_t* mem = m_host.GetGuestMemoryBase();

    RegisterThunk("glActiveTexture", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glActiveTexture(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glAttachShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glAttachShader(jit.Regs()[0], jit.Regs()[1]);
    });

    RegisterThunk("glBindAttribLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        if (name) glBindAttribLocation(jit.Regs()[0], jit.Regs()[1], name);
    });

    RegisterThunk("glBindBuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLuint buffer = jit.Regs()[1];
        if (target == GL_ARRAY_BUFFER) s_bound_array_buffer = buffer;
        else if (target == GL_ELEMENT_ARRAY_BUFFER) s_bound_element_buffer = buffer;
        glBindBuffer(target, buffer);
    });

    RegisterThunk("glBindFramebuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        s_bound_framebuffer = jit.Regs()[1];
        glBindFramebuffer(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBindRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBindRenderbuffer(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBindTexture", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBindTexture(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBlendFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBlendFunc(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]));
    });

    RegisterThunk("glBlendFuncSeparate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBlendFuncSeparate(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]),
                            static_cast<GLenum>(jit.Regs()[2]), static_cast<GLenum>(jit.Regs()[3]));
    });

    RegisterThunk("glBufferData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        GLsizeiptr size = static_cast<GLsizeiptr>(jit.Regs()[1]);
        const void* data = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]);
        GLenum usage = static_cast<GLenum>(jit.Regs()[3]);
        glBufferData(target, size, data, usage);
    });

    RegisterThunk("glMapBufferOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLenum access = static_cast<GLenum>(jit.Regs()[1]);
        if (access != GL_WRITE_ONLY_OES) {
            LOGE("glMapBufferOES unsupported access 0x%X", access);
            jit.Regs()[0] = 0;
            return;
        }

        GLint size = 0;
        glGetBufferParameteriv(target, GL_BUFFER_SIZE, &size);
        if (size <= 0) {
            jit.Regs()[0] = 0;
            return;
        }

        const uint32_t address = host.GuestAlloc(static_cast<size_t>(size), 16);
        if (!address) {
            jit.Regs()[0] = 0;
            return;
        }
        memset(GuestToHost(host.GetGuestMemoryBase(), address), 0, static_cast<size_t>(size));

        std::lock_guard<std::mutex> lock(s_mapped_buffers_mutex);
        auto [it, inserted] = s_mapped_buffers.emplace(target, GuestMappedBuffer{address, size});
        if (!inserted) {
            host.GuestFree(address);
            jit.Regs()[0] = 0;
            return;
        }
        jit.Regs()[0] = address;
    });

    RegisterThunk("glUnmapBufferOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        GuestMappedBuffer mapped;
        {
            std::lock_guard<std::mutex> lock(s_mapped_buffers_mutex);
            auto it = s_mapped_buffers.find(target);
            if (it == s_mapped_buffers.end()) {
                jit.Regs()[0] = GL_FALSE;
                return;
            }
            mapped = it->second;
            s_mapped_buffers.erase(it);
        }

        glBufferSubData(target, 0, mapped.size, GuestToHost(host.GetGuestMemoryBase(), mapped.address));
        host.GuestFree(mapped.address);
        jit.Regs()[0] = GL_TRUE;
    });

    RegisterThunk("glCheckFramebufferStatus", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCheckFramebufferStatus(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glClear", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glClear(static_cast<GLbitfield>(jit.Regs()[0]));
#if ARM32_BRIDGE_ENABLE_LOGGING
        if (++g_clear_calls <= 10) LOGI("glClear #%u mask=0x%X", g_clear_calls, jit.Regs()[0]);
#endif
    });

    RegisterThunk("glClearColor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float r = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float g = *reinterpret_cast<float*>(&jit.Regs()[1]);
        float b = *reinterpret_cast<float*>(&jit.Regs()[2]);
        float a = *reinterpret_cast<float*>(&jit.Regs()[3]);
        glClearColor(r, g, b, a);
    });

    RegisterThunk("glColorMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glColorMask(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glCompileShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint shader = jit.Regs()[0];
        glCompileShader(shader);
        GLint compiled = 0;
        glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
        if (!compiled) {
            char log[1024] = {};
            glGetShaderInfoLog(shader, sizeof(log), nullptr, log);

            // This one generated Telltale shader relies on EXT_shadow_samplers,
            // which Adreno 618 does not expose even though it does expose the
            // underlying OES depth textures.  Retry only the byte-exact shader
            // and only for the observed missing-extension compiler error.  A
            // regular sampler plus step(ref, depth) preserves the default
            // GL_LEQUAL comparison used by shadow2DEXT.
            const char* extensions = reinterpret_cast<const char*>(glGetString(GL_EXTENSIONS));
            if (strstr(log, "extension 'GL_EXT_shadow_samplers' is not supported") &&
                HasGlExtension(extensions, "GL_OES_depth_texture")) {
                std::string original_source;
                std::string rewritten_source;
                if (ReadShaderSource(shader, original_source) &&
                    RewriteDirectionalLightShadowHigh(original_source, rewritten_source)) {
                    const GLchar* rewritten_pointer = rewritten_source.c_str();
                    glShaderSource(shader, 1, &rewritten_pointer, nullptr);
                    glCompileShader(shader);
                    glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
                    if (compiled) {
                        LOGI("Shader %u DirectionalLightShadow_High: emulated EXT_shadow_samplers", shader);
                        return;
                    }

                    char retry_log[1024] = {};
                    glGetShaderInfoLog(shader, sizeof(retry_log), nullptr, retry_log);
                    LOGE("Shader %u shadow-sampler fallback failed: %s", shader, retry_log);
                }
            }

            LOGE("Shader %u compile failed: %s", shader, log);
#if ARM32_BRIDGE_ENABLE_GL_SHADER_DIAGNOSTICS
            GLint source_length = 0;
            glGetShaderiv(shader, GL_SHADER_SOURCE_LENGTH, &source_length);
            if (source_length > 1 && source_length <= 64 * 1024) {
                std::vector<char> source(static_cast<size_t>(source_length));
                GLsizei written = 0;
                glGetShaderSource(shader, source_length, &written, source.data());
                LOGE("Shader %u source begin (%d bytes)", shader, written);
                // Some Android loggers cap an individual payload at roughly 1 KiB.
                // Stay below that limit so the complete multi-line shader survives.
                constexpr GLsizei kLogChunk = 800;
                for (GLsizei offset = 0; offset < written; offset += kLogChunk) {
                    const GLsizei count = std::min(kLogChunk, written - offset);
                    LOGE("Shader %u source[%d]: %.*s", shader, offset, count, source.data() + offset);
                }
                LOGE("Shader %u source end", shader);
            }
#endif
        }
    });

    RegisterThunk("glCompressedTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLenum target = jit.Regs()[0];
        GLint level = jit.Regs()[1];
        GLenum internalformat = jit.Regs()[2];
        GLsizei width = jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        GLsizei height = host.MemoryRead32(sp);
        GLint border = host.MemoryRead32(sp + 4);
        GLsizei imageSize = host.MemoryRead32(sp + 8);
        const void* data = GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 12));
        glCompressedTexImage2D(target, level, internalformat, width, height, border, imageSize, data);
    });

    RegisterThunk("glCreateProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCreateProgram();
    });

    RegisterThunk("glCreateShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCreateShader(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glCullFace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glCullFace(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDeleteBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteBuffers(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDeleteFramebuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteFramebuffers(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDeleteProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteProgram(jit.Regs()[0]);
    });

    RegisterThunk("glDeleteRenderbuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteRenderbuffers(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDeleteShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteShader(jit.Regs()[0]);
    });

    RegisterThunk("glDeleteTextures", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteTextures(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDepthFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDepthFunc(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDepthMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDepthMask(static_cast<GLboolean>(jit.Regs()[0]));
    });

    RegisterThunk("glDisable", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDisable(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDisableVertexAttribArray", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDisableVertexAttribArray(jit.Regs()[0]);
    });

    RegisterThunk("glDrawArrays", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
#if ARM32_BRIDGE_ENABLE_LOGGING
        const GLenum before_error = glGetError();
#endif
        glDrawArrays(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLint>(jit.Regs()[1]), static_cast<GLsizei>(jit.Regs()[2]));
#if ARM32_BRIDGE_ENABLE_LOGGING
        const uint32_t count = ++g_draw_calls;
        if (count <= 10) {
            GLint fbo = 0, program = 0, viewport[4] = {}, scissor[4] = {};
            glGetIntegerv(GL_FRAMEBUFFER_BINDING, &fbo);
            glGetIntegerv(GL_CURRENT_PROGRAM, &program);
            glGetIntegerv(GL_VIEWPORT, viewport);
            glGetIntegerv(GL_SCISSOR_BOX, scissor);
            const GLboolean scissor_enabled = glIsEnabled(GL_SCISSOR_TEST);
            GLubyte pixel[4] = {};
            if (fbo == 0 && viewport[2] > 0 && viewport[3] > 0) {
                glReadPixels(viewport[0] + viewport[2] / 2, viewport[1] + viewport[3] / 2,
                             1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
            }
            const GLenum after_error = glGetError();
            LOGI("glDrawArrays #%u mode=0x%X count=%u fbo=%d program=%d viewport=%d,%d %dx%d scissor=%u,%u %ux%u enabled=%u pixel=%u,%u,%u,%u glError=0x%X->0x%X",
                 count, jit.Regs()[0], jit.Regs()[2], fbo, program, viewport[0], viewport[1], viewport[2], viewport[3],
                 scissor[0], scissor[1], scissor[2], scissor[3], scissor_enabled,
                 pixel[0], pixel[1], pixel[2], pixel[3], before_error, after_error);
        }
#endif
    });

    RegisterThunk("glDrawElements", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t indices_gaddr = jit.Regs()[3];
        const void* indices = (s_bound_element_buffer != 0) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(indices_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), indices_gaddr);
        glDrawElements(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLsizei>(jit.Regs()[1]),
                       static_cast<GLenum>(jit.Regs()[2]), indices);
#if ARM32_BRIDGE_ENABLE_LOGGING
        if (++g_draw_calls <= 10) LOGI("glDrawElements #%u mode=0x%X count=%u", g_draw_calls, jit.Regs()[0], jit.Regs()[1]);
#endif
    });

    RegisterThunk("glEnable", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glEnable(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glEnableVertexAttribArray", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glEnableVertexAttribArray(jit.Regs()[0]);
    });

    RegisterThunk("glFlush", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFlush();
    });

    RegisterThunk("glFramebufferRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFramebufferRenderbuffer(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glFramebufferTexture2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFramebufferTexture2D(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], host.MemoryRead32(jit.Regs()[13]));
    });

    RegisterThunk("glFrontFace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFrontFace(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glGenBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenBuffers(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenFramebuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenFramebuffers(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenRenderbuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenRenderbuffers(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenTextures", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenTextures(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenerateMipmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenerateMipmap(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glGetActiveAttrib", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        GLsizei* length = reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        GLint* size = reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp)));
        GLenum* type = reinterpret_cast<GLenum*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 4)));
        GLchar* name = reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8)));
        glGetActiveAttrib(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], length, size, type, name);
    });

    RegisterThunk("glGetActiveUniform", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        GLsizei* length = reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        GLint* size = reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp)));
        GLenum* type = reinterpret_cast<GLenum*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 4)));
        GLchar* name = reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8)));
        glGetActiveUniform(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], length, size, type, name);
    });

    RegisterThunk("glGetAttribLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glGetAttribLocation(jit.Regs()[0], reinterpret_cast<const GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGetError", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glGetError();
    });

    RegisterThunk("glGetIntegerv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetIntegerv(static_cast<GLenum>(jit.Regs()[0]),
                      reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGetProgramInfoLog", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLsizei* length = jit.Regs()[2] ?
            reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])) : nullptr;
        glGetProgramInfoLog(jit.Regs()[0], jit.Regs()[1], length,
                           reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glGetProgramiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetProgramiv(jit.Regs()[0], static_cast<GLenum>(jit.Regs()[1]),
                       reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glGetRenderbufferParameteriv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetRenderbufferParameteriv(jit.Regs()[0], jit.Regs()[1],
                                     reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glGetShaderInfoLog", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLsizei* length = jit.Regs()[2] ?
            reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])) : nullptr;
        glGetShaderInfoLog(jit.Regs()[0], jit.Regs()[1], length,
                          reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glGetShaderiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetShaderiv(jit.Regs()[0], static_cast<GLenum>(jit.Regs()[1]),
                      reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    // GL promises a pointer valid for the life of the context, and callers keep
    // it. One block per enum, so a capability check inside a frame loop costs
    // nothing after the first frame - GL_EXTENSIONS alone is a couple of KiB.
    RegisterThunk("glGetString", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::mutex m;
        static std::unordered_map<GLenum, uint32_t> cache;
        GLenum name = static_cast<GLenum>(jit.Regs()[0]);
        std::lock_guard<std::mutex> lock(m);
        auto it = cache.find(name);
        if (it == cache.end()) {
            const GLubyte* str = glGetString(name);
            uint32_t guest_addr = 0;
            if (str) {
                size_t len = strlen(reinterpret_cast<const char*>(str)) + 1;
                guest_addr = host.GuestAlloc(len);
                if (guest_addr) memcpy(host.GetGuestMemoryBase() + guest_addr, str, len);
            }
            it = cache.emplace(name, guest_addr).first;
        }
        jit.Regs()[0] = it->second;
    });

    RegisterThunk("glGetUniformLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glGetUniformLocation(jit.Regs()[0], reinterpret_cast<const GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glHint", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glHint(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]));
    });

    RegisterThunk("glLineWidth", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glLineWidth(*reinterpret_cast<float*>(&jit.Regs()[0]));
    });

    RegisterThunk("glLinkProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint prog = jit.Regs()[0];
        glLinkProgram(prog);
        GLint linked = 0;
        glGetProgramiv(prog, GL_LINK_STATUS, &linked);
        if (!linked) {
            char log[1024];
            glGetProgramInfoLog(prog, sizeof(log), nullptr, log);
            LOGE("Program %u link failed: %s", prog, log);
        }
    });

    RegisterThunk("glPixelStorei", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glPixelStorei(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glPolygonOffset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glPolygonOffset(*reinterpret_cast<float*>(&jit.Regs()[0]), *reinterpret_cast<float*>(&jit.Regs()[1]));
    });

    RegisterThunk("glReadPixels", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        GLenum format = host.MemoryRead32(sp);
        GLenum type = host.MemoryRead32(sp + 4);
        void* pixels = GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8));
        glReadPixels(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], format, type, pixels);
    });

    RegisterThunk("glRenderbufferStorage", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glRenderbufferStorage(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glScissor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLint x = jit.Regs()[0], y = jit.Regs()[1];
        GLsizei w = jit.Regs()[2], h = jit.Regs()[3];
        ScaleViewportToSurface(x, y, w, h);
        glScissor(x, y, w, h);
    });

    RegisterThunk("glShaderSource", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint shader = jit.Regs()[0];
        GLsizei count = jit.Regs()[1];
        uint32_t str_array_gaddr = jit.Regs()[2];
        uint32_t len_array_gaddr = jit.Regs()[3];

        std::vector<const char*> strings(count);
        for (GLsizei i = 0; i < count; ++i) {
            uint32_t str_gaddr = host.MemoryRead32(str_array_gaddr + i * 4);
            strings[i] = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), str_gaddr));
        }

        const GLint* lengths = len_array_gaddr ?
            reinterpret_cast<const GLint*>(GuestToHost(host.GetGuestMemoryBase(), len_array_gaddr)) : nullptr;

        glShaderSource(shader, count, strings.data(), lengths);
    });

    RegisterThunk("glTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLenum target = jit.Regs()[0];
        GLint level = jit.Regs()[1];
        GLint internalformat = jit.Regs()[2];
        GLsizei width = jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        GLsizei height = host.MemoryRead32(sp);
        GLint border = host.MemoryRead32(sp + 4);
        GLenum format = host.MemoryRead32(sp + 8);
        GLenum type = host.MemoryRead32(sp + 12);
        uint32_t pixels_gaddr = host.MemoryRead32(sp + 16);
        const void* pixels = (pixels_gaddr < 0x10000) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(pixels_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), pixels_gaddr);
        glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels);
    });

    RegisterThunk("glTexParameterf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glTexParameterf(jit.Regs()[0], jit.Regs()[1], *reinterpret_cast<float*>(&jit.Regs()[2]));
    });

    RegisterThunk("glTexParameteri", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glTexParameteri(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2]);
    });

    RegisterThunk("glUniform1f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1f(jit.Regs()[0], *reinterpret_cast<float*>(&jit.Regs()[1]));
    });

    RegisterThunk("glUniform1i", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1i(jit.Regs()[0], jit.Regs()[1]);
    });

    RegisterThunk("glUniform2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform2f(jit.Regs()[0], *reinterpret_cast<float*>(&jit.Regs()[1]), *reinterpret_cast<float*>(&jit.Regs()[2]));
    });

    RegisterThunk("glUniform3f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform3f(jit.Regs()[0], *reinterpret_cast<float*>(&jit.Regs()[1]),
                    *reinterpret_cast<float*>(&jit.Regs()[2]), *reinterpret_cast<float*>(&jit.Regs()[3]));
    });

    RegisterThunk("glUniform3fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform3fv(jit.Regs()[0], jit.Regs()[1],
                     reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glUniform4f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        uint32_t w_bits = host.MemoryRead32(sp);
        float w = *reinterpret_cast<float*>(&w_bits);
        glUniform4f(jit.Regs()[0], *reinterpret_cast<float*>(&jit.Regs()[1]),
                    *reinterpret_cast<float*>(&jit.Regs()[2]), *reinterpret_cast<float*>(&jit.Regs()[3]), w);
    });

    RegisterThunk("glUniform4fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform4fv(jit.Regs()[0], jit.Regs()[1],
                     reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glUniformMatrix3fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniformMatrix3fv(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                           reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glUniformMatrix4fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniformMatrix4fv(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                           reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glUseProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUseProgram(jit.Regs()[0]);
    });

    RegisterThunk("glVertexAttribPointer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint index = jit.Regs()[0];
        GLint size = jit.Regs()[1];
        GLenum type = jit.Regs()[2];
        GLboolean normalized = jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        GLsizei stride = host.MemoryRead32(sp);
        uint32_t ptr_gaddr = host.MemoryRead32(sp + 4);

        const void* ptr = (s_bound_array_buffer != 0) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(ptr_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), ptr_gaddr);

        glVertexAttribPointer(index, size, type, normalized, stride, ptr);
    });

    RegisterThunk("glViewport", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLint x = jit.Regs()[0], y = jit.Regs()[1];
        GLsizei w = jit.Regs()[2], h = jit.Regs()[3];
        ScaleViewportToSurface(x, y, w, h);
#if ARM32_BRIDGE_ENABLE_VFS_DIAGNOSTICS
        if (w >= 300 && h >= 300) {
            static std::mutex viewport_mutex;
            static std::unordered_set<uint64_t> seen_viewports;
            const uint64_t key = (static_cast<uint64_t>(s_bound_framebuffer != 0) << 63) |
                                 (static_cast<uint64_t>(static_cast<uint32_t>(w)) << 32) |
                                 static_cast<uint32_t>(h);
            std::lock_guard<std::mutex> lock(viewport_mutex);
            if (seen_viewports.size() < 64 && seen_viewports.insert(key).second)
                LOGI("MCSM viewport fbo=%u x=%d y=%d size=%dx%d surface=%ux%u virtual=%ux%u",
                     s_bound_framebuffer, x, y, w, h,
                     ThunkManager::s_screenWidth, ThunkManager::s_screenHeight,
                     ThunkManager::s_virtualWidth, ThunkManager::s_virtualHeight);
        }
#endif
        glViewport(x, y, w, h);
    });

    // Legacy GLES1/OES imports are function-pointer relocations in SDL2. Keep them typed
    // and guest-pointer-safe even when the active context is GLES2.
    RegisterThunk("glBindFramebufferOES", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        s_bound_framebuffer = jit.Regs()[1];
        glBindFramebuffer(GL_FRAMEBUFFER, jit.Regs()[1]);
    });
    RegisterThunk("glBlendFuncSeparateOES", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glBlendFuncSeparate(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });
    RegisterThunk("glCheckFramebufferStatusOES", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = glCheckFramebufferStatus(jit.Regs()[0]);
    });
    RegisterThunk("glColor4f", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glColor4f(ReadSF(jit, 0), ReadSF(jit, 1), ReadSF(jit, 2), ReadSF(jit, 3));
    });
    RegisterThunk("glDeleteFramebuffersOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[0]);
        const GLuint* framebuffers = count > 0
            ? static_cast<const GLuint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], static_cast<size_t>(count) * sizeof(GLuint)))
            : nullptr;
        if (count <= 0 || framebuffers) glDeleteFramebuffers(count, framebuffers);
    });
    RegisterThunk("glDisableClientState", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glDisableClientState(jit.Regs()[0]);
    });
    RegisterThunk("glDrawTexfOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        // provider-policy: glDrawTexfOES unsupported - void GLES1 entry point; no draw or synthetic guest GL error is produced.
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        (void)args.F32(); (void)args.F32(); (void)args.F32(); (void)args.F32(); (void)args.F32();
        LOGE("glDrawTexfOES unsupported by the GLES2 bridge; required use blocks graphics acceptance");
    });
    RegisterThunk("glEnableClientState", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glEnableClientState(jit.Regs()[0]);
    });
    RegisterThunk("glFinish", [](Dynarmic::A32::Jit&, DynarmicHost&) { glFinish(); });
    RegisterThunk("glFramebufferTexture2DOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFramebufferTexture2D(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], host.MemoryRead32(jit.Regs()[13]));
    });
    RegisterThunk("glGenFramebuffersOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[0]);
        GLuint* framebuffers = count > 0
            ? static_cast<GLuint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], static_cast<size_t>(count) * sizeof(GLuint)))
            : nullptr;
        if (count > 0 && framebuffers) glGenFramebuffers(count, framebuffers);
    });
    RegisterThunk("glGetBooleanv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const size_t count = GetGlStateValueCount(jit.Regs()[0]);
        GLboolean* values = static_cast<GLboolean*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], count * sizeof(GLboolean)));
        if (values) glGetBooleanv(jit.Regs()[0], values);
    });
    RegisterThunk("glLoadIdentity", [](Dynarmic::A32::Jit&, DynarmicHost&) { glLoadIdentity(); });
    RegisterThunk("glMatrixMode", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { glMatrixMode(jit.Regs()[0]); });
    RegisterThunk("glOrthof", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLfloat left = args.F32();
        const GLfloat right = args.F32();
        const GLfloat bottom = args.F32();
        const GLfloat top = args.F32();
        const GLfloat near_value = args.F32();
        const GLfloat far_value = args.F32();
        glOrthof(left, right, bottom, top, near_value, far_value);
    });
    RegisterThunk("glPopMatrix", [](Dynarmic::A32::Jit&, DynarmicHost&) { glPopMatrix(); });
    RegisterThunk("glPushMatrix", [](Dynarmic::A32::Jit&, DynarmicHost&) { glPushMatrix(); });
    RegisterThunk("glRotatef", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glRotatef(ReadSF(jit, 0), ReadSF(jit, 1), ReadSF(jit, 2), ReadSF(jit, 3));
    });
    RegisterThunk("glShaderBinary", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[0]);
        const GLuint* shaders = count > 0
            ? static_cast<const GLuint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], static_cast<size_t>(count) * sizeof(GLuint)))
            : nullptr;
        const GLsizei length = static_cast<GLsizei>(host.MemoryRead32(jit.Regs()[13]));
        const void* binary = length > 0
            ? GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[3], static_cast<size_t>(length))
            : nullptr;
        if (count > 0 && shaders && length > 0 && binary) glShaderBinary(count, shaders, jit.Regs()[2], binary, length);
    });
    RegisterThunk("glTexCoordPointer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei stride = static_cast<GLsizei>(jit.Regs()[2]);
        const uint32_t pointer = jit.Regs()[3];
        const void* data = s_bound_array_buffer ? reinterpret_cast<const void*>(static_cast<uintptr_t>(pointer))
                                                : GuestToHost(host.GetGuestMemoryBase(), pointer);
        glTexCoordPointer(jit.Regs()[0], jit.Regs()[1], stride, data);
    });
    RegisterThunk("glTexEnvf", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glTexEnvf(jit.Regs()[0], jit.Regs()[1], ReadSF(jit, 2));
    });
    RegisterThunk("glTexParameteriv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const size_t count = jit.Regs()[1] == GL_TEXTURE_CROP_RECT_OES ? 4 : 1;
        const GLint* values = static_cast<const GLint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[2], count * sizeof(GLint)));
        if (values) glTexParameteriv(jit.Regs()[0], jit.Regs()[1], values);
    });
    RegisterThunk("glTranslatef", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glTranslatef(ReadSF(jit, 0), ReadSF(jit, 1), ReadSF(jit, 2));
    });
    RegisterThunk("glVertexPointer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei stride = static_cast<GLsizei>(jit.Regs()[2]);
        const uint32_t pointer = jit.Regs()[3];
        const void* data = s_bound_array_buffer ? reinterpret_cast<const void*>(static_cast<uintptr_t>(pointer))
                                                : GuestToHost(host.GetGuestMemoryBase(), pointer);
        glVertexPointer(jit.Regs()[0], jit.Regs()[1], stride, data);
    });

    RegisterGles2CoreThunks(*this);
}
