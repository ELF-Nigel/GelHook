import os
import sys
import subprocess
import ctypes

HERE = os.path.dirname(os.path.abspath(__file__))

if sys.platform.startswith("win"):
    libname = "gelhook_py.dll"
elif sys.platform == "darwin":
    libname = "libgelhook_py.dylib"
else:
    libname = "libgelhook_py.so"

libpath = os.path.join(HERE, libname)


def build_library():
    print("Building demo library...")
    if sys.platform.startswith("win"):
        # Prefer MSVC if available
        cl = os.environ.get("CL", None)
        if cl is not None:
            cmd = ["cl", "/LD", "/O2", "/Fe:" + libname, "hook_lib.c"]
            subprocess.check_call(cmd, cwd=HERE)
        else:
            cmd = ["clang-cl", "/LD", "/O2", "/Fe:" + libname, "hook_lib.c"]
            subprocess.check_call(cmd, cwd=HERE)
    else:
        cmd = ["cc", "-shared", "-fPIC", "-O2", "-o", libname, "hook_lib.c"]
        subprocess.check_call(cmd, cwd=HERE)


if not os.path.exists(libpath):
    try:
        build_library()
    except Exception as e:
        print("Build failed:", e)
        print("See examples/python/README.md for manual build steps.")
        sys.exit(1)

lib = ctypes.CDLL(libpath)

lib.ghpy_init.argtypes = [ctypes.c_int]
lib.ghpy_init.restype = None

lib.ghpy_call_a.argtypes = [ctypes.c_int]
lib.ghpy_call_a.restype = ctypes.c_int

lib.ghpy_call_b.argtypes = [ctypes.c_int]
lib.ghpy_call_b.restype = ctypes.c_int

lib.ghpy_install_inline.argtypes = []
lib.ghpy_install_inline.restype = ctypes.c_int

lib.ghpy_install_site.argtypes = []
lib.ghpy_install_site.restype = ctypes.c_int

lib.ghpy_rehook_inline.argtypes = []
lib.ghpy_rehook_inline.restype = ctypes.c_int

lib.ghpy_uninstall_all.argtypes = []
lib.ghpy_uninstall_all.restype = ctypes.c_int

# Enable TRACE logging
lib.ghpy_init(4)

print("== Advanced Python Hook Demo ==")

print("A before:", lib.ghpy_call_a(5))
print("B before:", lib.ghpy_call_b(5))

rc = lib.ghpy_install_inline()
print("Install inline hook rc:", rc)
print("A after inline:", lib.ghpy_call_a(5))

rc = lib.ghpy_install_site()
print("Install site hook rc:", rc)
print("B after site:", lib.ghpy_call_b(5))

rc = lib.ghpy_rehook_inline()
print("Rehook inline rc:", rc)
print("A after rehook:", lib.ghpy_call_a(5))

lib.ghpy_uninstall_all()
print("A after uninstall:", lib.ghpy_call_a(5))
print("B after uninstall:", lib.ghpy_call_b(5))
