# Python Hook Demo (Advanced)

This demo builds a small shared library that uses GelHook internally, then calls it from Python via `ctypes`.
It demonstrates:

- Inline hook
- Site (mid-function) hook
- Rehook after restoring original bytes
- Structured logging

## Run

```bash
python3 hook_demo.py
```

The script builds the shared library automatically if it does not exist.

## Manual build (optional)

Linux:

```bash
cc -shared -fPIC -O2 -o libgelhook_py.so hook_lib.c
```

Windows (MSVC):

```bat
cl /LD /O2 /Fe:gelhook_py.dll hook_lib.c
```
