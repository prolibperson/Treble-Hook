/*
  _______ _____  ______ ____  _      ______
 |__   __|  __ \|  ____|  _ \| |    |  ____|
    | |  | |__) | |__  | |_) | |    | |__
    | |  |  _  /|  __| |  _ <| |    |  __|
    | |  | | \ \| |____| |_) | |____| |____
    |_|  |_|  \_\\______|____/|______|______|
                named after the fishing hook!

 crappy hooking library for x64 windows

 "what makes this special?"

 this lib inserts random padding instructions
 before the jump to the detour to bypass simple
 hooking scanners. hurray!

 usage:
    TB_create_hook(target_function, detour_function, &trampoline);
	TB_loop_create_hook(target_function, detour_function, expected_bytes, expected_length, &trampoline);
    TB_enable_hook(target_function);
    TB_disable_hook(target_function);
    TB_remove_hook(target_function);
    TB_remove_all_hooks();

*/

#pragma once
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <thread>
#include <vector>
#include <windows.h>

namespace treble_hook {

    constexpr size_t ABSOLUTE_JUMP_SIZE = 12; /* mov rax imm64 (10) + jmp rax (2) */

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
        static bool seeded = false;
        if (!seeded) {
            std::srand(static_cast<unsigned int>(std::time(nullptr)));
            seeded = true;
        }

        /* nop variants */
        static const uint8_t nop1[] = { 0x90 };
        static const uint8_t nop2[] = { 0x66, 0x90 };
        static const uint8_t nop3[] = { 0x0F, 0x1F, 0x00 };
        static const uint8_t nop4[] = { 0x0F, 0x1F, 0x40, 0x00 };
        static const uint8_t nop5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };

        const uint8_t* nops[] = { nop1, nop2, nop3, nop4, nop5 };
        const size_t nop_sizes[] = { sizeof(nop1), sizeof(nop2), sizeof(nop3),
            sizeof(nop4), sizeof(nop5) };
        const size_t num_nops = sizeof(nops) / sizeof(nops[0]);

        size_t pos = 0;
        while (pos < len) {
            /* make list of candidates */
            size_t remaining = len - pos;
            std::vector<size_t> candidates;
            for (size_t i = 0; i < num_nops; ++i) {
                if (nop_sizes[i] <= remaining)
                    candidates.push_back(i);
            }

            /* pick random nop variant */
            size_t choice = candidates[std::rand() % candidates.size()];

            /* copy */
            memcpy(dst + pos, nops[choice], nop_sizes[choice]);
            pos += nop_sizes[choice];
        }
    }

    /* x64 instruction length detection (vibecoded with claude cuz i aint using
     * another lib for disassembly) */
    static inline size_t get_instruction_length(uint8_t* addr)
    {
        uint8_t op = addr[0];

        // single byte NOP
        if (op == 0x90 || op == 0xCC)
            return 1;

        // push/pop registers
        if (op >= 0x50 && op <= 0x57)
            return 1; // push rax–rdi
        if (op >= 0x58 && op <= 0x5F)
            return 1; // pop rax–rdi
        if (op >= 0x41 && op <= 0x4F) { // REX prefix with push/pop
            uint8_t next = addr[1];
            if (next >= 0x50 && next <= 0x57)
                return 2; // push r8–r15
            if (next >= 0x58 && next <= 0x5F)
                return 2; // pop r8–r15
        }

        // function prologue common patterns
        if (op == 0x55)
            return 1; // push rbp
        if (op == 0x48) { // REX.W prefix
            uint8_t next = addr[1];
            if (next == 0x89 || next == 0x8B)
                return 3; // mov reg, reg
            if (next == 0x83)
                return 3; // add/sub imm8
            if (next == 0x8D)
                return 3; // lea
            if (next == 0xC7)
                return 7; // mov r/m64, imm32
        }

        // ret / call / jmp
        if (op == 0xC3 || op == 0xC2)
            return 1;
        if (op == 0xE8 || op == 0xE9)
            return 5; // call/jmp rel32

        // absolute indirect jump (jmp rax, rdx, etc)
        if (op == 0xFF) {
            uint8_t modrm = addr[1];
            uint8_t mod = (modrm & 0xC0) >> 6;
            uint8_t reg = (modrm & 0x38) >> 3;
            if (reg == 4 || reg == 5)
                return 2; // jmp/call r/m
            return 2;
        }

        return 1;
    }

    /* calc total length needed for complete instructions */
    static inline size_t calculate_hook_length(void* addr, size_t min_length)
    {
        uint8_t* p = (uint8_t*)addr;
        size_t total = 0;
        while (total < min_length) {
            total += get_instruction_length(p + total);
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
        size_t trampoline_size = hook_length + ABSOLUTE_JUMP_SIZE;
        void* trampoline = VirtualAlloc(nullptr, trampoline_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return nullptr;

        uint8_t* tramp = (uint8_t*)trampoline;
        memcpy(tramp, target, hook_length);
        tramp += hook_length;

        // absolute jump back
        tramp[0] = 0x48;
        tramp[1] = 0xB8;
        *(void**)(tramp + 2) = (uint8_t*)target + hook_length;
        tramp[10] = 0xFF;
        tramp[11] = 0xE0;

        FlushInstructionCache(GetCurrentProcess(), trampoline, trampoline_size);
        return trampoline;
    }

    /* check if already hooked */
    inline bool TB_is_already_hooked(void* addr)
    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        for (auto& h : g_hooks)
            if (h.target == addr && h.active)
                return true;
        return false;
    }

    /* create hook! */
    inline bool TB_create_hook(
        void* target, void* detour, void** out_trampoline = nullptr)
    {
        if (!target || !detour || TB_is_already_hooked(target))
            return false;
        std::lock_guard<std::mutex> lock(g_hook_mutex);

        size_t min_length = ABSOLUTE_JUMP_SIZE + 4;
        size_t hook_length = calculate_hook_length(target, min_length);
        if (hook_length > sizeof(hook::original))
            return false;

        void* trampoline = create_trampoline(target, hook_length);
        if (!trampoline)
            return false;

        hook h{};
        h.target = target;
        h.detour = detour;
        h.trampoline = trampoline;
        h.length = hook_length;
        h.active = true;
        h.enabled = false;

        memcpy(h.original, target, h.length);
        g_hooks.push_back(h);

        /* return trampoline pointer if requested :thinking: */
        if (out_trampoline)
            *out_trampoline = trampoline;
        return true;
    }

    /* create hook, but loop until expected bytes are present */
    inline bool TB_loop_create_hook(void* target, void* detour,
        const uint8_t* expected_bytes, size_t expected_length,
        void** out_trampoline = nullptr)
    {
        if (!target || !detour || !expected_bytes || expected_length == 0)
            return false;

        while (true) {
            if (memcmp(target, expected_bytes, expected_length) == 0)
                break;

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        return TB_create_hook(target, detour, out_trampoline);
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
                size_t padding_size = h.length - ABSOLUTE_JUMP_SIZE;
                if (padding_size > 0)
                    TB_insert_padding(p_target, padding_size);

                /* install hook jump after padding */
                size_t jump_pos = padding_size;
                p_target[jump_pos + 0] = 0x48; /* rex w */
                p_target[jump_pos + 1] = 0xB8; /* mov rax imm64 */
                *(void**)(p_target + jump_pos + 2) = h.detour;
                p_target[jump_pos + 10] = 0xFF; /* jmp rax */
                p_target[jump_pos + 11] = 0xE0;

                FlushInstructionCache(GetCurrentProcess(), p_target, h.length);
                VirtualProtect(target, h.length, old_protect, &old_protect);

                h.enabled = true;
                return true;
            }
        }
        return false;
    }

    /* disable hook */
    inline bool TB_disable_hook(void* target)
    {
        std::lock_guard<std::mutex> lock(g_hook_mutex);
        for (auto& h : g_hooks) {
            if (h.target == target && h.active && h.enabled) {
                DWORD old_protect;
                if (!VirtualProtect(
                    h.target, h.length, PAGE_EXECUTE_READWRITE, &old_protect))
                    return false;

                /* restore original bytes */
                memcpy(h.target, h.original, h.length);
                FlushInstructionCache(GetCurrentProcess(), h.target, h.length);
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
                if (it->enabled
                    && VirtualProtect(it->target, it->length,
                        PAGE_EXECUTE_READWRITE, &old_protect)) {
                    memcpy(it->target, it->original, it->length);
                    FlushInstructionCache(
                        GetCurrentProcess(), it->target, it->length);
                    VirtualProtect(
                        it->target, it->length, old_protect, &old_protect);
                }

                /* free trampoline */
                if (it->trampoline)
                    VirtualFree(it->trampoline, 0, MEM_RELEASE);

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
                    FlushInstructionCache(GetCurrentProcess(), h.target, h.length);
                    VirtualProtect(h.target, h.length, old_protect, &old_protect);
                }

                /* free trampoline */
                if (h.trampoline)
                    VirtualFree(h.trampoline, 0, MEM_RELEASE);
            }
        }
        g_hooks.clear();
    }

    /* maybe do some stuff with this in the future? idk */
    inline bool TB_initialize() { return true; }

    /* cleanup */
    inline void TB_uninitialize() { TB_remove_all_hooks(); }

} // namespace treble_hook
