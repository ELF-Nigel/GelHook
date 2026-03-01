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
            # Try clang-cl
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
