import ctypes
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

if sys.platform.startswith("win"):
    libname = "gelhook_py.dll"
elif sys.platform == "darwin":
    libname = "libgelhook_py.dylib"
else:
    libname = "libgelhook_py.so"

libpath = os.path.join(HERE, libname)

if not os.path.exists(libpath):
    print("Shared library not found:", libpath)
    print("Build it first. See examples/python/README.md")
    sys.exit(1)

lib = ctypes.CDLL(libpath)
lib.ghpy_call.argtypes = [ctypes.c_int]
lib.ghpy_call.restype = ctypes.c_int
lib.ghpy_install_hook.argtypes = []
lib.ghpy_install_hook.restype = ctypes.c_int
lib.ghpy_uninstall_hook.argtypes = []
lib.ghpy_uninstall_hook.restype = ctypes.c_int

print("Before hook:", lib.ghpy_call(5))

rc = lib.ghpy_install_hook()
print("Install hook rc:", rc)

print("After hook:", lib.ghpy_call(5))

lib.ghpy_uninstall_hook()
