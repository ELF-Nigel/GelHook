# GelHook

GelHook is a single-header, minimalistic, cross-platform hook library written in pure C for x86-64 systems.

## Status

This is an early skeleton with a simple absolute-jump hook (12-byte patch) and a trampoline. It does **not** decode instructions, so targets must have at least 12 bytes of safe, non-relocated instructions at the entry point.

## Usage

```c
#define GELHOOK_IMPLEMENTATION
#include "gelhook.h"

// ... see examples/basic.c
```

## Build

No build system required. Include `gelhook.h` in your project.

## Caveats

- x86-64 only
- 12-byte overwrite at function entry
- No instruction length decoding or relocation
- Not thread-safe during patching

## License

MIT
