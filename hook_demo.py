import os
import sys
import subprocess
import shutil

ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(ROOT, "build_demo")

EXAMPLES = [
    "gh_example_basic",
    "gh_example_bp",
    "gh_example_rehook",
    "gh_example_vtable",
    "gh_example_vtable_swap",
    "gh_example_site",
    "gh_example_manager",
    "gh_example_reentry",
]

WIN_ONLY = [
    "gh_example_iat",
    "gh_example_eat",
    "gh_example_hw_bp",
    "gh_example_guard",
    "gh_example_hotpatch",
]

LINUX_ONLY = [
    "gh_example_plt",
]


def run(cmd, cwd=None):
    print("+", " ".join(cmd))
    subprocess.check_call(cmd, cwd=cwd)


def build_examples():
    if shutil.which("cmake") is None:
        print("cmake not found. Please install cmake.")
        sys.exit(1)

    os.makedirs(BUILD_DIR, exist_ok=True)
    run(["cmake", "-S", ROOT, "-B", BUILD_DIR, "-DGELHOOK_BUILD_EXAMPLES=ON"])
    run(["cmake", "--build", BUILD_DIR, "--config", "Release"])


def find_exe(name):
    if sys.platform.startswith("win"):
        path = os.path.join(BUILD_DIR, "Release", name + ".exe")
    else:
        path = os.path.join(BUILD_DIR, name)
    return path


def run_examples():
    print("\n== Running examples ==")
    names = list(EXAMPLES)
    if sys.platform.startswith("win"):
        names += WIN_ONLY
    elif sys.platform.startswith("linux"):
        names += LINUX_ONLY

    for name in names:
        exe = find_exe(name)
        if not os.path.exists(exe):
            print(f"[skip] {name} (not built)")
            continue
        print(f"\n-- {name} --")
        try:
            run([exe], cwd=BUILD_DIR)
        except subprocess.CalledProcessError as e:
            print(f"[fail] {name}: {e}")


def run_python_demo():
    print("\n== Running Python demo ==")
    demo = os.path.join(ROOT, "examples", "python", "hook_demo.py")
    run([sys.executable, demo], cwd=os.path.dirname(demo))


def main():
    print("== GelHook Demo Runner ==")
    build_examples()
    run_examples()
    run_python_demo()
    print("\nDone.")


if __name__ == "__main__":
    main()
