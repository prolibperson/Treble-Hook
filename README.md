# Treble Hook

Treble Hook is a lightweight x64 hooking library for Windows, designed for stealthy inline function hooks with random padding to bypass simple hooking scanners.

## Features

* Inline function hooks for x64 Windows.
* Randomized padding instructions before the jump to detour.
* Trampolines with original instructions preserved.
* Easy hook management:

  * Create, enable, disable, and remove hooks.
  * Remove all hooks at once.
* Optional looped hook creation that waits for expected bytes before installing the hook.

## Installation

Clone this repository and include the header in your project:

```cpp
#include "treble.h"
```

No additional dependencies are required beyond standard Windows libraries.

## Usage

### Creating a Hook

```cpp
#include "treble.h"

void target_function();
void detour_function();

int main() {
    void* trampoline = nullptr;
    if (treble_hook::TB_create_hook(target_function, detour_function, &trampoline)) {
        treble_hook::TB_enable_hook(target_function);
    }

    target_function();

    treble_hook::TB_disable_hook(target_function);
    treble_hook::TB_remove_hook(target_function);
    return 0;
}
```

### Looped Hook Creation

This version waits until the target function contains the expected bytes before creating the hook:

```cpp
#include "treble.h"
#include <cstdint>

void target_function();
void detour_function();

int main() {
    uint8_t expected_bytes[] = { 0x48, 0x89, 0x5C, 0x24, 0x08 }; /* example */
    void* trampoline = nullptr;

    if (treble_hook::TB_loop_create_hook(target_function, detour_function, expected_bytes, sizeof(expected_bytes), &trampoline)) {
        treble_hook::TB_enable_hook(target_function);
    }

    target_function();

    treble_hook::TB_disable_hook(target_function);
    treble_hook::TB_remove_hook(target_function);
    return 0;
}
```

### Hooking Functions in DLLs Using Offsets

```cpp
#include "treble.h"
#include <windows.h>

uintptr_t dll_base = (uintptr_t)GetModuleHandle(nullptr);
uintptr_t function_offset = 0x1234; /* example offset */
void* target = (void*)(dll_base + function_offset);

void detour_function();
void* trampoline = nullptr;

if (treble_hook::TB_create_hook(target, detour_function, &trampoline)) {
    treble_hook::TB_enable_hook(target);
}
```

### Disabling and Removing Hooks

```cpp
treble_hook::TB_disable_hook(target_function);
treble_hook::TB_remove_hook(target_function);
treble_hook::TB_remove_all_hooks();
```

## API Reference

* `TB_create_hook(target, detour, out_trampoline)` Creates a hook but does not enable it by default.
* `TB_loop_create_hook(target, detour, expected_bytes, expected_length, out_trampoline)` Loops until expected bytes appear, then creates the hook.
* `TB_enable_hook(target)` Enables a previously created hook.
* `TB_disable_hook(target)` Disables a hook.
* `TB_remove_hook(target)` Removes a hook completely.
* `TB_remove_all_hooks()` Removes all hooks.
* `TB_uninitialize()` Cleans up all hooks and resources.

## License

This project is licensed under the **GPL-3.0 License**. See [LICENSE](LICENSE) for details.
