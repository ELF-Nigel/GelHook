# GelHook

GelHook is a single-header, advanced user-mode hook library written in pure C for x86-64 on Windows and Linux. It is designed to be portable, minimal in dependencies, and competitive with established user-mode detour libraries while keeping the codebase approachable and auditable.

## Highlights

- Single-header (`gelhook.h`) implementation
- x86-64 inline detours with safe prologue relocation
- Relative and absolute jump patches with near-trampoline allocation
- Rehook support (repair overwritten detours)
- Windows IAT hooks + Linux PLT/GOT hooks
- VTable/VFunc pointer swaps
- User-mode software breakpoint hooks
- User-mode hardware breakpoint hooks (Windows, per-thread)
- Hook manager API (batch enable/disable)
- Optional external disassembler backend via a small decoder interface (templates for Capstone/Zydis)

## Status

This repo contains a full user-mode feature set focused on Windows + Linux x86-64. It does **not** implement kernel-mode or stealth/anti-anti-cheat behavior.

## Build

```bash
cmake -S . -B build -DGELHOOK_BUILD_EXAMPLES=ON
cmake --build build --config Release
```

## Examples

- `examples/basic.c` inline detour
- `examples/breakpoint.c` software breakpoint hook
- `examples/iat.c` IAT hook (Windows)
- `examples/hw_breakpoint.c` hardware breakpoint hook (Windows)
- `examples/plt.c` PLT/GOT hook (Linux)
- `examples/vtable.cpp` vtable swap (C++)
- `examples/rehook.c` rehook stress test
- `examples/python/` Python ctypes demo

## Extras

- `extras/decoder_capstone.c` adapter template (requires Capstone)
- `extras/decoder_zydis.c` adapter template (requires Zydis)

## Usage

```c
#define GELHOOK_IMPLEMENTATION
#include "gelhook.h"

// See examples/basic.c
```

## API Sketch

```c
// Inline hook
gh_hook hook;
if (gh_init_hook(&hook, (void*)target, (void*)replacement) == GH_OK) {
  gh_enable_hook(&hook);
}

// Manager
gh_hook_manager mgr;
gh_manager_init(&mgr, 8);
gh_manager_add(&mgr, &hook);
gh_manager_enable_all(&mgr);
```

## Caveats

- x86-64 only
- User-mode only
- Inlined decoder is intentionally conservative; you can plug in Capstone/Zydis by providing a decoder callback
- Thread-safety during patching depends on suspend strategy

## License

MIT
