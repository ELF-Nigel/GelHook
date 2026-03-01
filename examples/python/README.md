# Python Hook Demo

This demo builds a small shared library that uses GelHook internally, then calls it from Python via `ctypes`.

## Run (one command)

```bash
python3 hook_demo.py
```

The script will build the shared library automatically if it does not exist.

## Manual build (optional)

Linux:

```bash
cc -shared -fPIC -O2 -o libgelhook_py.so hook_lib.c
```

Windows (MSVC):

```bat
cl /LD /O2 /Fe:gelhook_py.dll hook_lib.c
```
