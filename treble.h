/*
  _______ _____  ______ ____  _      ______
 |__   __|  __ \|  ____|  _ \| |    |  ____|
    | |  | |__) | |__  | |_) | |    | |__
    | |  |  _  /|  __| |  _ <| |    |  __|
    | |  | | \ \| |____| |_) | |____| |____
    |_|  |_|  \_\______|____/|______|______|
	            named after the fishing hook!


 crappy hooking library for x64 windows
 
 "what makes this special?" 

 this lib inserts random padding instructions
 before the jump to the detour to bypass simple 
 hooking scanners. hurray!

 usage:
	TB_create_hook(target_function, detour_function, &trampoline);
	TB_enable_hook(target_function);
	TB_disable_hook(target_function);
	TB_remove_hook(target_function);
	TB_remove_all_hooks();

*/


#pragma once
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>
#include <windows.h>

namespace treble_hook {

    struct hook {
        void* target;
        void* detour;
        void* trampoline;
        uint8_t original[32];
        size_t length;
        bool active;
        bool enabled;
    };

    inline std::vector<hook> g_hooks;
    inline std::mutex g_hook_mutex;

    /* generate random instructions for padding 
       (literally what makes this hooking lib special i think) 
       :thinking: */
    inline void TB_insert_padding(uint8_t* dst, size_t len)
    {
        size_t pos = 0;
        uint64_t seed = (uint32_t)((uintptr_t)dst ^ GetTickCount64());

        while (pos < len) {
            seed = seed * 1103515245 + 12345; /* simple lcg :sunglasses: */
            uint8_t choice = seed & 0x7;

            switch (choice) {
            case 0: /* nop variants */
                if (pos + 1 <= len) {
                    dst[pos++] = 0x90; /* nop */
                }
                break;
            case 1: /* multi byte nop 66 90 */
                if (pos + 2 <= len) {
                    dst[pos++] = 0x66;
                    dst[pos++] = 0x90;
                }
                break;
            case 2: /* lea with no effect lea eax [eax+0] */
                if (pos + 3 <= len) {
                    dst[pos++] = 0x8d;
                    dst[pos++] = 0x40;
                    dst[pos++] = 0x00;
                }
                break;
            case 3: /* mov reg reg no effect */
                if (pos + 2 <= len) {
                    dst[pos++] = 0x89;
                    dst[pos++] = 0xc0; /* mov eax eax */
                }
                break;
            case 4: /* push pop same register */
                if (pos + 2 <= len) {
                    uint8_t reg = (seed >> 8) & 0x7;
                    dst[pos++] = 0x50 + reg; /* push reg */
                    dst[pos++] = 0x58 + reg; /* pop reg */
                }
                break;
            default: /* fallback to simple nop */
                if (pos < len) {
                    dst[pos++] = 0x90; /* nop */
                }
                break;
            }
        }
    }

    /* x64 instruction length detection that i 
       vibecoded cuz i dont wanna add a disassembler 
       :skull: */
    inline size_t get_instruction_length(uint8_t* addr)
    {
        uint8_t* p = addr;
        size_t len = 1;

        while (*p == 0x40 || *p == 0x41 || *p == 0x42 || *p == 0x43
            ||
            *p == 0x44 || *p == 0x45 || *p == 0x46 || *p == 0x47 || *p == 0x48
            || *p == 0x49 || *p == 0x4a || *p == 0x4b || *p == 0x4c || *p == 0x4d
            || *p == 0x4e || *p == 0x4f || *p == 0x66 || *p == 0x67
            ||
            *p == 0xf2 || *p == 0xf3) {
            p++;
            len++;
        }

        uint8_t opcode = *p++;
        len++;

        if (opcode == 0x0f) {
            opcode = *p++;
            len++;
        }

        switch (opcode) {
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
        case 0x58:
        case 0x59:
        case 0x5a:
        case 0x5b:
        case 0x5c:
        case 0x5d:
        case 0x5e:
        case 0x5f:
        case 0x90:
        case 0xc3:
        case 0xcc:
            break;

        case 0x6a:
            len += 1;
            break;

        case 0x68:
        case 0xb8:
        case 0xb9:
        case 0xba:
        case 0xbb:
        case 0xbc:
        case 0xbd:
        case 0xbe:
        case 0xbf:
            len += 4;
            break;

        case 0x48:
            return get_instruction_length(addr);

        default:
            if ((*p & 0xc0) != 0xc0) {
                len++;
                uint8_t modrm = *p;

                if ((modrm & 0x07) == 0x04 && (modrm & 0xc0) != 0xc0) {
                    len++;
                }

                switch (modrm & 0xc0) {
                case 0x40:
                    len += 1;
                    break;
                case 0x80:
                    len += 4;
                    break;
                }
            }
            else {
                len++;
            }
            break;
        }

        return len;
    }

    /* calc total length needed for complete instructions */
    inline size_t calculate_hook_length(void* addr, size_t min_length)
    {
        uint8_t* p = (uint8_t*)addr;
        size_t total = 0;

        while (total < min_length) {
            size_t inst_len = get_instruction_length(p + total);
            if (inst_len == 0) {
                return (min_length + 7) & ~7;
            }
            total += inst_len;
        }

        return total;
    }

    /* allocate executable memory for trampoline */
    inline void* allocate_trampoline(size_t size)
    {
        return VirtualAlloc(
            nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    /* create tramp with original instructions + jmp back */
    inline void* create_trampoline(void* target, size_t hook_length)
    {
        /* alloc tramp original bytes + jmp back 14 bytes for absolute jump */
        size_t trampoline_size = hook_length + 14;
        void* trampoline = allocate_trampoline(trampoline_size);
        if (!trampoline)
            return nullptr;

        uint8_t* tramp = (uint8_t*)trampoline;

        /* copy original instructions */
        memcpy(tramp, target, hook_length);
        tramp += hook_length;

        /* add absolute jmp back to original function + hook_length */
        void* return_addr = (uint8_t*)target + hook_length;

        /* mov rax return_addr 10 bytes */
        tramp[0] = 0x48; /* rex w */
        tramp[1] = 0xb8; /* mov rax imm64 */
        *(void**)(tramp + 2) = return_addr;

        /* jmp rax 2 bytes */
        tramp[10] = 0xff;
        tramp[11] = 0xe0;

        return trampoline;
    }

    inline bool TB_is_already_hooked(void* addr)
    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        for (auto& h : g_hooks) {
            if (h.target == addr && h.active)
                return true;
        }
        return false;
    }

    /* create hook! */
    inline bool TB_create_hook(
        void* target, void* detour, void** original = nullptr)
    {
        if (!target || !detour || TB_is_already_hooked(target))
            return false;

        std::lock_guard<std::mutex> lock(g_hook_mutex);

        size_t min_length = 16; /* minimum for padding + jump */
        size_t hook_length = calculate_hook_length(target, min_length);

        if (hook_length > sizeof(hook::original)) {
            return false; /* too many bytes needed :( */
        }

        /* create trampoline first */
        void* trampoline = create_trampoline(target, hook_length);
        if (!trampoline)
            return false;

        /* prepare hook structure */
        hook h{};
        h.target = target;
        h.detour = detour;
        h.trampoline = trampoline;
        h.length = hook_length;
        h.active = true;
        h.enabled = false;

        /* save orig bytes */
        memcpy(h.original, target, hook_length);

        g_hooks.push_back(h);

        /* return trampoline pointer if requested :thinking: */
        if (original) {
            *original = trampoline;
        }

        return true;
    }

    /* enable hook! */
    inline bool TB_enable_hook(void* target)
    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        for (auto& h : g_hooks) {
            if (h.target == target && h.active && !h.enabled) {
                DWORD old_protect;
                uint8_t* p_target = (uint8_t*)target;

                if (!VirtualProtect(
                    p_target, h.length, PAGE_EXECUTE_READWRITE, &old_protect))
                    return false;

                /* calculate padding size, always leave 12 bytes for the jmp! */
                size_t padding_size = h.length - 12;

                /* insert padding at the beginning... */
                if (padding_size > 0) {
                    TB_insert_padding(p_target, padding_size);
                }

                /* install hook jump after padding */
                size_t jump_pos = padding_size;
                p_target[jump_pos + 0] = 0x48; /* rex w */
                p_target[jump_pos + 1] = 0xb8; /* mov rax imm64 */
                *(void**)(p_target + jump_pos + 2) = h.detour;
                p_target[jump_pos + 10] = 0xff; /* jmp rax */
                p_target[jump_pos + 11] = 0xe0;

                VirtualProtect(target, h.length, old_protect, &old_protect);
                h.enabled = true;
                return true;
            }
        }
        return false;
    }

    inline bool TB_disable_hook(void* target)
    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        for (auto& h : g_hooks) {
            if (h.target == target && h.active && h.enabled) {
                DWORD old_protect;
                if (!VirtualProtect(
                    h.target, h.length, PAGE_EXECUTE_READWRITE, &old_protect))
                    return false;

                /* restore original bytes temp */
                memcpy(h.target, h.original, h.length);
                VirtualProtect(h.target, h.length, old_protect, &old_protect);

                h.enabled = false;
                return true;
            }
        }
        return false;
    }

    /* remove hook completely */
    inline bool TB_remove_hook(void* target)
    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        for (auto it = g_hooks.begin(); it != g_hooks.end(); ++it) {
            if (it->target == target && it->active) {
                DWORD old_protect;

                /* restore original bytes if currently enabled */
                if (it->enabled) {
                    if (VirtualProtect(it->target, it->length,
                        PAGE_EXECUTE_READWRITE, &old_protect)) {
                        memcpy(it->target, it->original, it->length);
                        VirtualProtect(
                            it->target, it->length, old_protect, &old_protect);
                    }
                }

                /* free trampoline */
                if (it->trampoline) {
                    VirtualFree(it->trampoline, 0, MEM_RELEASE);
                }

                /* remove from list */
                g_hooks.erase(it);
                return true;
            }
        }
        return false;
    }

    /* remove all hooks */
    inline void TB_remove_all_hooks()
    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        for (auto& h : g_hooks) {
            if (h.active) {
                DWORD old_protect;

                /* restore original bytes if enabled */
                if (h.enabled
                    && VirtualProtect(
                        h.target, h.length, PAGE_EXECUTE_READWRITE, &old_protect)) {
                    memcpy(h.target, h.original, h.length);
                    VirtualProtect(h.target, h.length, old_protect, &old_protect);
                }

                /* free trampoline */
                if (h.trampoline) {
                    VirtualFree(h.trampoline, 0, MEM_RELEASE);
                }
            }
        }
        g_hooks.clear();
    }

    /* maybe do some stuff with this in the future? idk */
    inline bool TB_initialize()
    {
        return true;
    }

    /* cleanup */
    inline void TB_uninitialize() { TB_remove_all_hooks(); }
} // namespace treble_hook
