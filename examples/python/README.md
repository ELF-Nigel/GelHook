# Python Hook Demo

This demo builds a small shared library that uses GelHook internally, then calls it from Python via `ctypes`.

## Build (Linux)

```bash
gcc -shared -fPIC -O2 -o libgelhook_py.so hook_lib.c
```

## Build (Windows, MSVC)

```bat
cl /LD /O2 /Fe:gelhook_py.dll hook_lib.c
```

## Run

```bash
python3 hook_demo.py
```
