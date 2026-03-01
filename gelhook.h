#pragma once

/*
  GelHook - single-header x86_64 user-mode hook library (pure C)
  MIT License
*/

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(_WIN64)
  #define GH_PLATFORM_WINDOWS 1
#else
  #define GH_PLATFORM_POSIX 1
#endif

#if GH_PLATFORM_POSIX
  #if defined(_GNU_SOURCE)
    #define GH_HAS_GNU_SOURCE 1
  #else
    #define GH_HAS_GNU_SOURCE 0
  #endif
#endif

#if defined(__x86_64__) || defined(_M_X64)
  #define GH_ARCH_X64 1
#else
  #error "GelHook currently supports x86_64 only."
#endif

#ifndef GELHOOK_API
  #define GELHOOK_API
#endif

#ifndef GH_MAX_STOLEN
  #define GH_MAX_STOLEN 64
#endif

#ifndef GH_MAX_BREAKPOINTS
  #define GH_MAX_BREAKPOINTS 64
#endif

#ifndef GH_MAX_HW_BREAKPOINTS
  #define GH_MAX_HW_BREAKPOINTS 4
#endif

#ifndef GH_ENABLE_IAT
  #define GH_ENABLE_IAT 1
#endif

#ifndef GH_ENABLE_PLT
  #define GH_ENABLE_PLT 1
#endif

#ifndef GH_ENABLE_VTABLE
  #define GH_ENABLE_VTABLE 1
#endif

#ifndef GH_ENABLE_BREAKPOINTS
  #define GH_ENABLE_BREAKPOINTS 1
#endif

#ifndef GH_ENABLE_HW_BREAKPOINTS
  #define GH_ENABLE_HW_BREAKPOINTS 1
#endif

#ifndef GH_ENABLE_THREAD_SUSPEND
  #define GH_ENABLE_THREAD_SUSPEND 1
#endif

#define GH_ABS_JMP_SIZE 12
#define GH_REL_JMP_SIZE 5
#define GH_ABS_CALL_SIZE 12
#define GH_JCC_ABS_SIZE 14

typedef enum gh_status {
  GH_OK = 0,
  GH_ERR_INVALID_ARG = -1,
  GH_ERR_UNSUPPORTED = -2,
  GH_ERR_ALLOC = -3,
  GH_ERR_PROTECT = -4,
  GH_ERR_STATE = -5,
  GH_ERR_DECODE = -6,
  GH_ERR_RANGE = -7,
  GH_ERR_NOT_FOUND = -8
} gh_status;

typedef enum gh_hook_kind {
  GH_HOOK_INLINE = 0,
  GH_HOOK_IAT = 1,
  GH_HOOK_PLT = 2,
  GH_HOOK_VTABLE = 3,
  GH_HOOK_SITE = 4,
  GH_HOOK_EAT = 5,
  GH_HOOK_HOTPATCH = 6
} gh_hook_kind;

typedef struct gh_hook_options {
  int prefer_rel_jump;
  int suspend_threads;
  int allocate_near;
  int allow_code_cave;
  size_t max_stolen;
} gh_hook_options;

typedef struct gh_hook {
  gh_hook_kind kind;
  void *target;
  void *replacement;
  void *trampoline;
  size_t patch_size;
  size_t stolen_len;
  unsigned char original[GH_MAX_STOLEN];
  int enabled;
  void *extra;
} gh_hook;

typedef struct gh_hook_manager {
  gh_hook *hooks;
  size_t count;
  size_t cap;
} gh_hook_manager;

typedef void (*gh_thread_fn)(void);

typedef struct gh_thread_callbacks {
  gh_thread_fn suspend_all;
  gh_thread_fn resume_all;
} gh_thread_callbacks;

typedef enum gh_rel_kind {
  GH_REL_NONE = 0,
  GH_REL_JMP = 1,
  GH_REL_CALL = 2,
  GH_REL_JCC = 3
} gh_rel_kind;

typedef struct gh_inst {
  size_t len;
  size_t disp_offset;
  size_t disp_size;
  size_t imm_offset;
  size_t imm_size;
  int has_modrm;
  uint8_t modrm;
  int is_rel;
  gh_rel_kind rel_kind;
  size_t rel_offset;
  size_t rel_size;
  int is_rip_rel;
} gh_inst;

typedef gh_status (*gh_decode_fn)(const uint8_t *code, size_t max, gh_inst *out);

typedef struct gh_decoder {
  gh_decode_fn decode;
} gh_decoder;

#if GH_ENABLE_BREAKPOINTS

typedef void (*gh_bp_callback)(void *ip, void *user);

typedef struct gh_breakpoint {
  void *addr;
  uint8_t original;
  gh_bp_callback callback;
  void *user;
  int enabled;
} gh_breakpoint;

#if GH_PLATFORM_WINDOWS
typedef void (*gh_guard_callback)(void *ip, void *user);
typedef struct gh_guard_hook {
  void *addr;
  size_t size;
  gh_guard_callback callback;
  void *user;
  int enabled;
} gh_guard_hook;
#endif

#if GH_ENABLE_HW_BREAKPOINTS
typedef struct gh_hw_breakpoint {
  void *addr;
  void *thread;
  gh_bp_callback callback;
  void *user;
  int enabled;
  int slot;
} gh_hw_breakpoint;
#endif

#endif

GELHOOK_API gh_status gh_init_hook(gh_hook *hook, void *target, void *replacement);
GELHOOK_API gh_status gh_init_hook_ex(gh_hook *hook, void *target, void *replacement, const gh_hook_options *options);
GELHOOK_API gh_status gh_init_hook_at(gh_hook *hook, void *site, void *replacement, size_t patch_size, const gh_hook_options *options);
GELHOOK_API gh_status gh_init_hotpatch_hook(gh_hook *hook, void *target, void *replacement, const gh_hook_options *options);
GELHOOK_API gh_status gh_enable_hook(gh_hook *hook);
GELHOOK_API gh_status gh_disable_hook(gh_hook *hook);
GELHOOK_API gh_status gh_destroy_hook(gh_hook *hook);
GELHOOK_API gh_status gh_rehook(gh_hook *hook);
GELHOOK_API void *gh_get_trampoline(const gh_hook *hook);
GELHOOK_API const char *gh_last_error(void);
GELHOOK_API void gh_set_decoder(const gh_decoder *dec);

GELHOOK_API gh_status gh_manager_init(gh_hook_manager *mgr, size_t initial_cap);
GELHOOK_API gh_status gh_manager_add(gh_hook_manager *mgr, const gh_hook *hook);
GELHOOK_API gh_status gh_manager_enable_all(gh_hook_manager *mgr);
GELHOOK_API gh_status gh_manager_disable_all(gh_hook_manager *mgr);
GELHOOK_API gh_status gh_manager_enable_all_atomic(gh_hook_manager *mgr, const gh_hook_options *options);
GELHOOK_API void gh_manager_destroy(gh_hook_manager *mgr);

#if GH_ENABLE_VTABLE
GELHOOK_API gh_status gh_vtable_hook(void **vtable, size_t index, void *replacement, void **original_out);
GELHOOK_API gh_status gh_vtable_swap(void *obj, size_t vtable_count, size_t index,
                                    void *replacement, void **original_out, void ***new_table_out);
#endif

#if GH_ENABLE_IAT
#if GH_PLATFORM_WINDOWS
GELHOOK_API gh_status gh_iat_hook(const char *module_name, const char *import_dll,
                                 const char *func_name, void *replacement, void **original_out);
#endif
#endif

#if GH_ENABLE_PLT
GELHOOK_API gh_status gh_plt_hook(const char *symbol_name, void *replacement, void **original_out);
#endif

#if GH_PLATFORM_WINDOWS
GELHOOK_API gh_status gh_eat_hook(const char *module_name, const char *export_name,
                                 void *replacement, void **original_out);
GELHOOK_API gh_status gh_iat_hook_module(void *module_base, const char *import_dll,
                                         const char *func_name, void *replacement, void **original_out);
GELHOOK_API gh_status gh_iat_hook_all(const char *import_dll, const char *func_name,
                                      void *replacement, void **original_out);
GELHOOK_API gh_status gh_delay_iat_hook(const char *module_name, const char *import_dll,
                                        const char *func_name, void *replacement, void **original_out);
GELHOOK_API gh_status gh_eat_hook_module(void *module_base, const char *export_name,
                                         void *replacement, void **original_out);
GELHOOK_API void *gh_resolve_export_forwarder(void *module_base, const char *export_name);
GELHOOK_API void *gh_resolve_export_by_ordinal(void *module_base, uint16_t ordinal);
GELHOOK_API gh_status gh_tls_callback_hook(const char *module_name, size_t index,
                                           void *replacement, void **original_out);
GELHOOK_API void *gh_find_code_cave_module(void *module_base, size_t size);
#endif

GELHOOK_API void *gh_resolve_symbol(const char *module_name, const char *symbol_name);

typedef struct gh_module_info {
  void *base;
  size_t size;
  const char *name;
} gh_module_info;

typedef int (*gh_module_enum_cb)(const gh_module_info *info, void *user);
GELHOOK_API int gh_enum_modules(gh_module_enum_cb cb, void *user);

typedef struct gh_export_info {
  const char *name;
  uint16_t ordinal;
  void *address;
  int is_forwarder;
  const char *forwarder;
} gh_export_info;

typedef int (*gh_export_enum_cb)(const gh_export_info *info, void *user);
GELHOOK_API int gh_enum_exports(void *module_base, gh_export_enum_cb cb, void *user);

typedef struct gh_reentry_guard {
  int max_depth;
} gh_reentry_guard;

GELHOOK_API int gh_reentry_enter(const gh_reentry_guard *guard);
GELHOOK_API void gh_reentry_leave(const gh_reentry_guard *guard);

#if GH_ENABLE_BREAKPOINTS
GELHOOK_API gh_status gh_breakpoint_add(gh_breakpoint *bp, void *addr, gh_bp_callback cb, void *user);
GELHOOK_API gh_status gh_breakpoint_remove(gh_breakpoint *bp);
#if GH_PLATFORM_WINDOWS
GELHOOK_API gh_status gh_guard_hook_add(gh_guard_hook *hook, void *addr, size_t size, gh_guard_callback cb, void *user);
GELHOOK_API gh_status gh_guard_hook_remove(gh_guard_hook *hook);
#endif
#if GH_ENABLE_HW_BREAKPOINTS
#if GH_PLATFORM_WINDOWS
GELHOOK_API gh_status gh_hw_breakpoint_add(gh_hw_breakpoint *bp, void *addr, void *thread, gh_bp_callback cb, void *user);
GELHOOK_API gh_status gh_hw_breakpoint_remove(gh_hw_breakpoint *bp);
#endif
#endif
#endif

GELHOOK_API void gh_set_thread_callbacks(const gh_thread_callbacks *cbs);

#ifdef __cplusplus
}
#endif

#ifdef GELHOOK_IMPLEMENTATION

#if GH_PLATFORM_WINDOWS
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <tlhelp32.h>
  #include <psapi.h>
  #include <dbghelp.h>
  #include <delayimp.h>
  #include <winternl.h>
  #include <intrin.h>
#else
  #include <sys/mman.h>
  #include <unistd.h>
  #include <dlfcn.h>
  #include <link.h>
  #include <elf.h>
  #include <signal.h>
  #include <ucontext.h>
#if defined(__linux__)
  #include <sys/ucontext.h>
#endif
#endif

#ifndef GH_MIN
  #define GH_MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

static char g_gh_last_error[128];
static gh_thread_callbacks g_gh_thread_cbs;
static gh_decoder g_gh_decoder;

static void gh_set_error(const char *msg) {
  size_t n = strlen(msg);
  if (n >= sizeof(g_gh_last_error)) n = sizeof(g_gh_last_error) - 1;
  memcpy(g_gh_last_error, msg, n);
  g_gh_last_error[n] = '\0';
}

const char *gh_last_error(void) {
  return g_gh_last_error;
}

void gh_set_thread_callbacks(const gh_thread_callbacks *cbs) {
  if (cbs) {
    g_gh_thread_cbs = *cbs;
  } else {
    g_gh_thread_cbs.suspend_all = NULL;
    g_gh_thread_cbs.resume_all = NULL;
  }
}

void gh_set_decoder(const gh_decoder *dec) {
  if (dec) {
    g_gh_decoder = *dec;
  } else {
    g_gh_decoder.decode = NULL;
  }
}

static void gh_threads_suspend_if_enabled(const gh_hook_options *opts);
static void gh_threads_resume_if_enabled(const gh_hook_options *opts);

static void gh_write_abs_jump(void *at, void *to, unsigned char out[GH_ABS_JMP_SIZE]) {
  unsigned char *p = out;
  /* mov rax, imm64 */
  p[0] = 0x48; p[1] = 0xB8;
  *(uint64_t *)(p + 2) = (uint64_t)(uintptr_t)to;
  /* jmp rax */
  p[10] = 0xFF; p[11] = 0xE0;
  if (at) memcpy(at, p, GH_ABS_JMP_SIZE);
}

static void gh_write_abs_call(uint8_t *at, void *to) {
  /* mov rax, imm64; call rax */
  at[0] = 0x48; at[1] = 0xB8;
  *(uint64_t *)(at + 2) = (uint64_t)(uintptr_t)to;
  at[10] = 0xFF; at[11] = 0xD0;
}

static void gh_write_rel_jump(void *at, void *to, unsigned char out[GH_REL_JMP_SIZE]) {
  unsigned char *p = out;
  intptr_t rel = (intptr_t)((unsigned char *)to - ((unsigned char *)at + GH_REL_JMP_SIZE));
  p[0] = 0xE9;
  *(int32_t *)(p + 1) = (int32_t)rel;
  if (at) memcpy(at, p, GH_REL_JMP_SIZE);
}

static int gh_rel32_fits(void *from, void *to, size_t instr_size) {
  intptr_t rel = (intptr_t)((unsigned char *)to - ((unsigned char *)from + instr_size));
  return rel >= INT32_MIN && rel <= INT32_MAX;
}

static void *gh_find_code_cave(void *near_addr, size_t size) {
#if GH_PLATFORM_WINDOWS
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  size_t page_size = info.dwPageSize;
#else
  long page_size = sysconf(_SC_PAGESIZE);
#endif
  uintptr_t start = (uintptr_t)near_addr & ~(uintptr_t)(page_size - 1);
  uint8_t *p = (uint8_t *)start;
  for (size_t i = 0; i + size <= (size_t)page_size; ++i) {
    size_t j = 0;
    for (; j < size; ++j) {
      uint8_t b = p[i + j];
      if (b != 0x90 && b != 0xCC) break;
    }
    if (j == size) return p + i;
  }
  return NULL;
}

static gh_status gh_protect_rwxa(void *addr, size_t size, int *old_prot_out) {
#if GH_PLATFORM_WINDOWS
  DWORD old_prot = 0;
  if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old_prot)) {
    gh_set_error("VirtualProtect failed");
    return GH_ERR_PROTECT;
  }
  if (old_prot_out) *old_prot_out = (int)old_prot;
  return GH_OK;
#else
  long page_size = sysconf(_SC_PAGESIZE);
  uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(page_size - 1);
  uintptr_t end = ((uintptr_t)addr + size + (uintptr_t)(page_size - 1)) & ~(uintptr_t)(page_size - 1);
  if (mprotect((void *)start, (size_t)(end - start), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    gh_set_error("mprotect failed");
    return GH_ERR_PROTECT;
  }
  (void)old_prot_out;
  return GH_OK;
#endif
}

static gh_status gh_restore_prot(void *addr, size_t size, int old_prot) {
#if GH_PLATFORM_WINDOWS
  DWORD tmp = 0;
  if (!VirtualProtect(addr, size, (DWORD)old_prot, &tmp)) {
    gh_set_error("VirtualProtect restore failed");
    return GH_ERR_PROTECT;
  }
  return GH_OK;
#else
  (void)addr; (void)size; (void)old_prot;
  return GH_OK;
#endif
}

static void *gh_alloc_exec(size_t size) {
#if GH_PLATFORM_WINDOWS
  return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
  void *p = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (p == MAP_FAILED) return NULL;
  return p;
#endif
}

static void gh_free_exec(void *p, size_t size) {
#if GH_PLATFORM_WINDOWS
  (void)size;
  VirtualFree(p, 0, MEM_RELEASE);
#else
  munmap(p, size);
#endif
}

static void *gh_alloc_exec_near(void *target, size_t size) {
  uintptr_t base = (uintptr_t)target;
  uintptr_t min = base >= (1ull << 31) ? base - (1ull << 31) : 0;
  uintptr_t max = base + (1ull << 31);
  size_t step = 0x10000;

#if GH_PLATFORM_WINDOWS
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  uintptr_t gran = (uintptr_t)info.dwAllocationGranularity;
  for (uintptr_t addr = (base & ~(gran - 1)); addr >= min; addr -= gran) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void *)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
      if (mbi.State == MEM_FREE) {
        void *p = VirtualAlloc((void *)addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) return p;
      }
    }
    if (addr < gran) break;
  }
  for (uintptr_t addr = (base & ~(gran - 1)); addr <= max; addr += gran) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void *)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
      if (mbi.State == MEM_FREE) {
        void *p = VirtualAlloc((void *)addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) return p;
      }
    }
    if (addr + gran < addr) break;
  }
  return NULL;
#else
  for (uintptr_t addr = (base & ~(step - 1)); addr >= min; addr -= step) {
    void *p = mmap((void *)addr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p != MAP_FAILED) return p;
    if (addr < step) break;
  }
  for (uintptr_t addr = (base & ~(step - 1)); addr <= max; addr += step) {
    void *p = mmap((void *)addr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p != MAP_FAILED) return p;
    if (addr + step < addr) break;
  }
  return NULL;
#endif
}

static void *gh_find_code_cave_module(void *module_base, size_t size) {
#if GH_PLATFORM_WINDOWS
  if (!module_base || size == 0) return NULL;
  uint8_t *base = (uint8_t *)module_base;
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    DWORD chars = sec[i].Characteristics;
    if ((chars & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
    uint8_t *start = base + sec[i].VirtualAddress;
    size_t len = (size_t)sec[i].Misc.VirtualSize;
    for (size_t off = 0; off + size <= len; ++off) {
      size_t j = 0;
      for (; j < size; ++j) {
        uint8_t b = start[off + j];
        if (b != 0x90 && b != 0xCC) break;
      }
      if (j == size) return start + off;
    }
  }
#endif
  (void)module_base; (void)size;
  return NULL;
}

/* ---------------- Minimal x86-64 instruction decoder ---------------- */

static int gh_is_prefix(uint8_t b) {
  if (b == 0xF0 || b == 0xF2 || b == 0xF3) return 1;
  if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26) return 1;
  if (b == 0x64 || b == 0x65) return 1;
  if (b == 0x66 || b == 0x67) return 1;
  return 0;
}

static int gh_opcode_requires_modrm(uint8_t op1, uint8_t op2, int two_byte) {
  (void)op2;
  if (!two_byte) {
    switch (op1) {
      case 0x00: case 0x01: case 0x02: case 0x03:
      case 0x08: case 0x09: case 0x0A: case 0x0B:
      case 0x10: case 0x11: case 0x12: case 0x13:
      case 0x18: case 0x19: case 0x1A: case 0x1B:
      case 0x20: case 0x21: case 0x22: case 0x23:
      case 0x28: case 0x29: case 0x2A: case 0x2B:
      case 0x30: case 0x31: case 0x32: case 0x33:
      case 0x38: case 0x39: case 0x3A: case 0x3B:
      case 0x80: case 0x81: case 0x83:
      case 0x84: case 0x85:
      case 0x86: case 0x87:
      case 0x88: case 0x89: case 0x8A: case 0x8B:
      case 0x8D:
      case 0x8F:
      case 0xC0: case 0xC1: case 0xC6: case 0xC7:
      case 0xD0: case 0xD1: case 0xD2: case 0xD3:
      case 0xF6: case 0xF7:
      case 0xFE: case 0xFF:
        return 1;
      default:
        return 0;
    }
  }
  switch (op1) {
    case 0x0F:
      switch (op2) {
        case 0xAF:
        case 0xB6: case 0xB7: case 0xBE: case 0xBF:
        case 0x1F:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
          return 1;
        default:
          return 0;
      }
    default:
      return 0;
  }
}

static void gh_parse_modrm(const uint8_t *code, size_t *idx, gh_inst *out) {
  uint8_t modrm = code[*idx];
  out->has_modrm = 1;
  out->modrm = modrm;
  (*idx)++;

  uint8_t mod = (modrm >> 6) & 0x3;
  uint8_t rm = modrm & 0x7;

  if (mod != 3 && rm == 4) {
    uint8_t sib = code[*idx];
    (void)sib;
    (*idx)++;
    uint8_t base = sib & 0x7;
    if (mod == 0 && base == 5) {
      out->disp_offset = *idx;
      out->disp_size = 4;
      (*idx) += 4;
    }
  }

  if (mod == 0 && rm == 5) {
    out->disp_offset = *idx;
    out->disp_size = 4;
    (*idx) += 4;
    out->is_rip_rel = 1;
  } else if (mod == 1) {
    out->disp_offset = *idx;
    out->disp_size = 1;
    (*idx) += 1;
  } else if (mod == 2) {
    out->disp_offset = *idx;
    out->disp_size = 4;
    (*idx) += 4;
  }
}

static gh_status gh_decode_inst_default(const uint8_t *code, size_t max, gh_inst *out) {
  size_t idx = 0;
  uint8_t op1 = 0, op2 = 0;
  int two_byte = 0;
  int rex_w = 0;

  memset(out, 0, sizeof(*out));

  while (idx < max) {
    uint8_t b = code[idx];
    if (b >= 0x40 && b <= 0x4F) {
      rex_w = (b & 0x8) != 0;
      idx++;
      continue;
    }
    if (gh_is_prefix(b)) {
      idx++;
      continue;
    }
    break;
  }

  if (idx >= max) return GH_ERR_DECODE;

  op1 = code[idx++];
  if (op1 == 0x0F) {
    if (idx >= max) return GH_ERR_DECODE;
    op2 = code[idx++];
    two_byte = 1;
  }

  /* Relative branches */
  if (!two_byte && (op1 == 0xE8 || op1 == 0xE9)) {
    out->is_rel = 1;
    out->rel_kind = (op1 == 0xE8) ? GH_REL_CALL : GH_REL_JMP;
    out->rel_offset = idx; out->rel_size = 4;
    idx += 4; out->len = idx;
    return idx <= max ? GH_OK : GH_ERR_DECODE;
  }
  if (!two_byte && op1 == 0xEB) {
    out->is_rel = 1; out->rel_kind = GH_REL_JMP;
    out->rel_offset = idx; out->rel_size = 1;
    idx += 1; out->len = idx;
    return idx <= max ? GH_OK : GH_ERR_DECODE;
  }
  if (two_byte && op1 == 0x0F && (op2 >= 0x80 && op2 <= 0x8F)) {
    out->is_rel = 1; out->rel_kind = GH_REL_JCC;
    out->rel_offset = idx; out->rel_size = 4;
    idx += 4; out->len = idx;
    return idx <= max ? GH_OK : GH_ERR_DECODE;
  }
  if (!two_byte && (op1 >= 0x70 && op1 <= 0x7F)) {
    out->is_rel = 1; out->rel_kind = GH_REL_JCC;
    out->rel_offset = idx; out->rel_size = 1;
    idx += 1; out->len = idx;
    return idx <= max ? GH_OK : GH_ERR_DECODE;
  }

  /* Immediate-only instructions */
  if (!two_byte && (op1 == 0x68)) { idx += 4; out->len = idx; return idx <= max ? GH_OK : GH_ERR_DECODE; }
  if (!two_byte && (op1 == 0x6A)) { idx += 1; out->len = idx; return idx <= max ? GH_OK : GH_ERR_DECODE; }
  if (!two_byte && (op1 >= 0xB8 && op1 <= 0xBF)) {
    idx += rex_w ? 8 : 4;
    out->len = idx;
    return idx <= max ? GH_OK : GH_ERR_DECODE;
  }

  /* Simple one-byte instructions */
  if (!two_byte) {
    switch (op1) {
      case 0x50: case 0x51: case 0x52: case 0x53:
      case 0x54: case 0x55: case 0x56: case 0x57:
      case 0x58: case 0x59: case 0x5A: case 0x5B:
      case 0x5C: case 0x5D: case 0x5E: case 0x5F:
      case 0x90: case 0x9C: case 0x9D:
      case 0xC3: case 0xC9:
        out->len = idx;
        return GH_OK;
      default:
        break;
    }
  }

  if (gh_opcode_requires_modrm(op1, op2, two_byte)) {
    if (idx >= max) return GH_ERR_DECODE;
    gh_parse_modrm(code, &idx, out);

    if (!two_byte) {
      switch (op1) {
        case 0x80: case 0x82: case 0x83:
          out->imm_offset = idx; out->imm_size = 1; idx += 1; break;
        case 0x81:
          out->imm_offset = idx; out->imm_size = 4; idx += 4; break;
        case 0xC6:
          out->imm_offset = idx; out->imm_size = 1; idx += 1; break;
        case 0xC7:
          out->imm_offset = idx; out->imm_size = 4; idx += 4; break;
        case 0xF6:
          out->imm_offset = idx; out->imm_size = 1; idx += 1; break;
        case 0xF7:
          out->imm_offset = idx; out->imm_size = 4; idx += 4; break;
        default:
          break;
      }
    }

    out->len = idx;
    return idx <= max ? GH_OK : GH_ERR_DECODE;
  }

  gh_set_error("unsupported instruction");
  return GH_ERR_UNSUPPORTED;
}

static gh_status gh_decode_inst(const uint8_t *code, size_t max, gh_inst *out) {
  if (g_gh_decoder.decode) return g_gh_decoder.decode(code, max, out);
  return gh_decode_inst_default(code, max, out);
}

static void gh_fixup_rip_rel(uint8_t *dst, const uint8_t *src, const gh_inst *inst, const uint8_t *src_ip, uint8_t *dst_ip) {
  if (!inst->is_rip_rel || inst->disp_size != 4) return;
  int32_t disp = *(const int32_t *)(src + inst->disp_offset);
  const uint8_t *abs_target = src_ip + inst->len + disp;
  int64_t new_disp = (int64_t)(abs_target - (dst_ip + inst->len));
  *(int32_t *)(dst + inst->disp_offset) = (int32_t)new_disp;
}

static size_t gh_emit_rel_rewrite(uint8_t *dst, const uint8_t *src, const gh_inst *inst, const uint8_t *src_ip) {
  int64_t rel = 0;
  if (inst->rel_size == 1) rel = *(const int8_t *)(src + inst->rel_offset);
  else rel = *(const int32_t *)(src + inst->rel_offset);
  const uint8_t *abs_target = src_ip + inst->len + rel;

  if (inst->rel_kind == GH_REL_CALL) {
    gh_write_abs_call(dst, (void *)abs_target);
    return GH_ABS_CALL_SIZE;
  }
  if (inst->rel_kind == GH_REL_JMP) {
    gh_write_abs_jump(dst, (void *)abs_target, dst);
    return GH_ABS_JMP_SIZE;
  }
  if (inst->rel_kind == GH_REL_JCC) {
    uint8_t cc = 0;
    if (inst->rel_size == 1) {
      cc = src[0] - 0x70;
    } else {
      cc = src[1] - 0x80;
    }
    dst[0] = (uint8_t)(0x70 + cc);
    dst[1] = (uint8_t)GH_ABS_JMP_SIZE; /* skip abs jmp */
    gh_write_abs_jump(dst + 2, (void *)abs_target, dst + 2);
    return GH_JCC_ABS_SIZE;
  }

  return 0;
}

static gh_status gh_build_trampoline(gh_hook *hook, const gh_hook_options *opts) {
  uint8_t *src = (uint8_t *)hook->target;
  size_t max = opts && opts->max_stolen ? opts->max_stolen : GH_MAX_STOLEN;
  size_t needed = hook->patch_size;
  size_t src_off = 0;
  size_t dst_off = 0;
  size_t tramp_cap = max * 4 + 64;

  if (max > GH_MAX_STOLEN) max = GH_MAX_STOLEN;

  if (opts && opts->allocate_near) {
    hook->trampoline = gh_alloc_exec_near(hook->target, tramp_cap);
  } else {
    hook->trampoline = gh_alloc_exec(tramp_cap);
  }

  if (!hook->trampoline) {
    gh_set_error("trampoline alloc failed");
    return GH_ERR_ALLOC;
  }

  while (src_off < needed) {
    gh_inst inst;
    gh_status st = gh_decode_inst(src + src_off, max - src_off, &inst);
    if (st != GH_OK) return st;

    if (inst.is_rel) {
      size_t wrote = gh_emit_rel_rewrite((uint8_t *)hook->trampoline + dst_off,
                                         src + src_off, &inst, src + src_off);
      if (wrote == 0) {
        gh_set_error("failed to rewrite relative branch");
        return GH_ERR_UNSUPPORTED;
      }
      dst_off += wrote;
      src_off += inst.len;
      continue;
    }

    memcpy((uint8_t *)hook->trampoline + dst_off, src + src_off, inst.len);
    gh_fixup_rip_rel((uint8_t *)hook->trampoline + dst_off, src + src_off,
                     &inst, src + src_off, (uint8_t *)hook->trampoline + dst_off);
    dst_off += inst.len;
    src_off += inst.len;

    if (src_off > max) {
      gh_set_error("stolen bytes exceed maximum");
      return GH_ERR_UNSUPPORTED;
    }
  }

  hook->stolen_len = src_off;
  memcpy(hook->original, src, src_off);

  gh_write_abs_jump((uint8_t *)hook->trampoline + dst_off,
                    (uint8_t *)hook->target + src_off,
                    (uint8_t *)hook->trampoline + dst_off);

  return GH_OK;
}

static gh_status gh_prepare_inline_hook(gh_hook *hook, const gh_hook_options *opts) {
  int use_rel = opts ? opts->prefer_rel_jump : 1;
  int allow_cave = opts ? opts->allow_code_cave : 0;
  void *cave = NULL;

  if (use_rel && gh_rel32_fits(hook->target, hook->replacement, GH_REL_JMP_SIZE)) {
    hook->patch_size = GH_REL_JMP_SIZE;
  } else {
    if (allow_cave) {
      cave = gh_find_code_cave(hook->target, GH_ABS_JMP_SIZE);
#if GH_PLATFORM_WINDOWS
      if (!cave) {
        cave = gh_find_code_cave_module(GetModuleHandleA(NULL), GH_ABS_JMP_SIZE);
      }
#endif
      if (cave && gh_rel32_fits(hook->target, cave, GH_REL_JMP_SIZE)) {
        hook->patch_size = GH_REL_JMP_SIZE;
        hook->extra = cave;
      } else {
        hook->patch_size = GH_ABS_JMP_SIZE;
      }
    } else {
      hook->patch_size = GH_ABS_JMP_SIZE;
    }
  }

  return gh_build_trampoline(hook, opts);
}

gh_status gh_init_hook_ex(gh_hook *hook, void *target, void *replacement, const gh_hook_options *options) {
  if (!hook || !target || !replacement) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }

  memset(hook, 0, sizeof(*hook));
  hook->kind = GH_HOOK_INLINE;
  hook->target = target;
  hook->replacement = replacement;

  return gh_prepare_inline_hook(hook, options);
}

gh_status gh_init_hook(gh_hook *hook, void *target, void *replacement) {
  gh_hook_options opts;
  opts.prefer_rel_jump = 1;
  opts.suspend_threads = 1;
  opts.allocate_near = 1;
  opts.allow_code_cave = 1;
  opts.max_stolen = GH_MAX_STOLEN;
  return gh_init_hook_ex(hook, target, replacement, &opts);
}

gh_status gh_init_hook_at(gh_hook *hook, void *site, void *replacement, size_t patch_size, const gh_hook_options *options) {
  if (!hook || !site || !replacement || patch_size == 0) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }

  memset(hook, 0, sizeof(*hook));
  hook->kind = GH_HOOK_SITE;
  hook->target = site;
  hook->replacement = replacement;
  hook->patch_size = patch_size;

  return gh_build_trampoline(hook, options);
}

gh_status gh_init_hotpatch_hook(gh_hook *hook, void *target, void *replacement, const gh_hook_options *options) {
  if (!hook || !target || !replacement) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }

  uint8_t *t = (uint8_t *)target;
  uint8_t *pre = t - 5;
  if (!((t[0] == 0x8B && t[1] == 0xFF) || (t[0] == 0x90 && t[1] == 0x90))) {
    gh_set_error("hotpatch requires 2-byte prologue");
    return GH_ERR_UNSUPPORTED;
  }

  for (int i = 0; i < 5; ++i) {
    if (pre[i] != 0x90 && pre[i] != 0xCC) {
      gh_set_error("hotpatch slot missing");
      return GH_ERR_UNSUPPORTED;
    }
  }

  memset(hook, 0, sizeof(*hook));
  hook->kind = GH_HOOK_HOTPATCH;
  hook->target = target;
  hook->replacement = replacement;
  hook->patch_size = 2;
  hook->extra = pre;

  memcpy(hook->original, t, 2);
  memcpy(hook->original + 2, pre, 5);
  hook->stolen_len = 2;

  return gh_build_trampoline(hook, options);
}

static gh_status gh_apply_patch(gh_hook *hook) {
  int old_prot = 0;
  gh_status st = gh_protect_rwxa(hook->target, hook->patch_size, &old_prot);
  if (st != GH_OK) return st;

  if (hook->kind == GH_HOOK_HOTPATCH && hook->extra) {
    uint8_t *pre = (uint8_t *)hook->extra;
    int pre_old = 0;
    gh_status stp = gh_protect_rwxa(pre, GH_ABS_JMP_SIZE, &pre_old);
    if (stp != GH_OK) return stp;
    gh_write_abs_jump(pre, hook->replacement, pre);
    (void)gh_restore_prot(pre, GH_ABS_JMP_SIZE, pre_old);

    uint8_t patch[2];
    patch[0] = 0xEB;
    patch[1] = (uint8_t)(-7);
    memcpy(hook->target, patch, 2);

    st = gh_restore_prot(hook->target, hook->patch_size, old_prot);
    if (st != GH_OK) return st;
    return GH_OK;
  }

  if (hook->patch_size == GH_REL_JMP_SIZE) {
    unsigned char patch[GH_REL_JMP_SIZE];
    void *dst = hook->replacement;
    if (hook->extra) {
      void *cave = hook->extra;
      int cave_old = 0;
      gh_status stc = gh_protect_rwxa(cave, GH_ABS_JMP_SIZE, &cave_old);
      if (stc != GH_OK) return stc;
      gh_write_abs_jump(cave, hook->replacement, (unsigned char *)cave);
      (void)gh_restore_prot(cave, GH_ABS_JMP_SIZE, cave_old);
      dst = cave;
    }
    gh_write_rel_jump(hook->target, dst, patch);
    memcpy(hook->target, patch, GH_REL_JMP_SIZE);
  } else {
    unsigned char patch[GH_ABS_JMP_SIZE];
    gh_write_abs_jump(NULL, hook->replacement, patch);
    memcpy(hook->target, patch, GH_ABS_JMP_SIZE);
  }

  st = gh_restore_prot(hook->target, hook->patch_size, old_prot);
  if (st != GH_OK) return st;

  return GH_OK;
}

gh_status gh_enable_hook(gh_hook *hook) {
  if (!hook || !hook->target || !hook->replacement) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }
  if (hook->enabled) {
    gh_set_error("already enabled");
    return GH_ERR_STATE;
  }

  gh_hook_options opts;
  opts.prefer_rel_jump = 1;
  opts.suspend_threads = 1;
  opts.allocate_near = 1;
  opts.allow_code_cave = 1;
  opts.max_stolen = GH_MAX_STOLEN;

  gh_threads_suspend_if_enabled(&opts);
  gh_status st = gh_apply_patch(hook);
  gh_threads_resume_if_enabled(&opts);

  if (st != GH_OK) return st;
  hook->enabled = 1;
  return GH_OK;
}

gh_status gh_rehook(gh_hook *hook) {
  if (!hook || !hook->target) return GH_ERR_INVALID_ARG;
  if (!hook->enabled) return GH_ERR_STATE;

  if (hook->kind == GH_HOOK_HOTPATCH) {
    return gh_apply_patch(hook);
  }

  if (hook->patch_size == GH_REL_JMP_SIZE) {
    unsigned char expected[GH_REL_JMP_SIZE];
    void *dst = hook->extra ? hook->extra : hook->replacement;
    gh_write_rel_jump(hook->target, dst, expected);
    if (memcmp(hook->target, expected, GH_REL_JMP_SIZE) == 0) return GH_OK;
  } else {
    unsigned char expected[GH_ABS_JMP_SIZE];
    gh_write_abs_jump(NULL, hook->replacement, expected);
    if (memcmp(hook->target, expected, GH_ABS_JMP_SIZE) == 0) return GH_OK;
  }

  return gh_apply_patch(hook);
}

gh_status gh_disable_hook(gh_hook *hook) {
  if (!hook || !hook->target) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }
  if (!hook->enabled) {
    gh_set_error("not enabled");
    return GH_ERR_STATE;
  }

  if (hook->kind == GH_HOOK_HOTPATCH && hook->extra) {
    uint8_t *pre = (uint8_t *)hook->extra;
    int pre_old = 0;
    gh_status stp = gh_protect_rwxa(pre, 5, &pre_old);
    if (stp != GH_OK) return stp;
    memcpy(pre, hook->original + 2, 5);
    (void)gh_restore_prot(pre, 5, pre_old);

    int old_prot_hp = 0;
    gh_status st_hp = gh_protect_rwxa(hook->target, 2, &old_prot_hp);
    if (st_hp != GH_OK) return st_hp;
    memcpy(hook->target, hook->original, 2);
    st_hp = gh_restore_prot(hook->target, 2, old_prot_hp);
    if (st_hp != GH_OK) return st_hp;

    hook->enabled = 0;
    return GH_OK;
  }

  int old_prot = 0;
  gh_status st = gh_protect_rwxa(hook->target, hook->stolen_len, &old_prot);
  if (st != GH_OK) return st;

  memcpy(hook->target, hook->original, hook->stolen_len);

  st = gh_restore_prot(hook->target, hook->stolen_len, old_prot);
  if (st != GH_OK) return st;

  hook->enabled = 0;
  return GH_OK;
}

gh_status gh_destroy_hook(gh_hook *hook) {
  if (!hook) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }
  if (hook->enabled) {
    gh_status st = gh_disable_hook(hook);
    if (st != GH_OK) return st;
  }
  if (hook->trampoline) {
    gh_free_exec(hook->trampoline, hook->stolen_len + GH_ABS_JMP_SIZE);
    hook->trampoline = NULL;
  }
  return GH_OK;
}

void *gh_get_trampoline(const gh_hook *hook) {
  return hook ? hook->trampoline : NULL;
}

/* ---------------- Hook manager ---------------- */

gh_status gh_manager_init(gh_hook_manager *mgr, size_t initial_cap) {
  if (!mgr) return GH_ERR_INVALID_ARG;
  memset(mgr, 0, sizeof(*mgr));
  if (initial_cap == 0) initial_cap = 8;
  mgr->hooks = (gh_hook *)calloc(initial_cap, sizeof(gh_hook));
  if (!mgr->hooks) return GH_ERR_ALLOC;
  mgr->cap = initial_cap;
  return GH_OK;
}

gh_status gh_manager_add(gh_hook_manager *mgr, const gh_hook *hook) {
  if (!mgr || !hook) return GH_ERR_INVALID_ARG;
  if (mgr->count >= mgr->cap) {
    size_t new_cap = mgr->cap * 2;
    gh_hook *next = (gh_hook *)realloc(mgr->hooks, new_cap * sizeof(gh_hook));
    if (!next) return GH_ERR_ALLOC;
    mgr->hooks = next;
    mgr->cap = new_cap;
  }
  mgr->hooks[mgr->count++] = *hook;
  return GH_OK;
}

gh_status gh_manager_enable_all(gh_hook_manager *mgr) {
  if (!mgr) return GH_ERR_INVALID_ARG;
  for (size_t i = 0; i < mgr->count; ++i) {
    gh_status st = gh_enable_hook(&mgr->hooks[i]);
    if (st != GH_OK) return st;
  }
  return GH_OK;
}

gh_status gh_manager_disable_all(gh_hook_manager *mgr) {
  if (!mgr) return GH_ERR_INVALID_ARG;
  for (size_t i = 0; i < mgr->count; ++i) {
    gh_status st = gh_disable_hook(&mgr->hooks[i]);
    if (st != GH_OK) return st;
  }
  return GH_OK;
}

gh_status gh_manager_enable_all_atomic(gh_hook_manager *mgr, const gh_hook_options *options) {
  if (!mgr) return GH_ERR_INVALID_ARG;

  gh_threads_suspend_if_enabled(options);
  for (size_t i = 0; i < mgr->count; ++i) {
    gh_status st = gh_apply_patch(&mgr->hooks[i]);
    if (st != GH_OK) {
      for (size_t j = 0; j < i; ++j) {
        (void)gh_disable_hook(&mgr->hooks[j]);
      }
      gh_threads_resume_if_enabled(options);
      return st;
    }
    mgr->hooks[i].enabled = 1;
  }
  gh_threads_resume_if_enabled(options);
  return GH_OK;
}

void gh_manager_destroy(gh_hook_manager *mgr) {
  if (!mgr) return;
  free(mgr->hooks);
  memset(mgr, 0, sizeof(*mgr));
}

/* ---------------- VTable hook ---------------- */

#if GH_ENABLE_VTABLE

gh_status gh_vtable_hook(void **vtable, size_t index, void *replacement, void **original_out) {
  if (!vtable || !replacement) return GH_ERR_INVALID_ARG;
  if (original_out) *original_out = vtable[index];

  int old_prot = 0;
  gh_status st = gh_protect_rwxa(&vtable[index], sizeof(void *), &old_prot);
  if (st != GH_OK) return st;

  vtable[index] = replacement;

  st = gh_restore_prot(&vtable[index], sizeof(void *), old_prot);
  if (st != GH_OK) return st;

  return GH_OK;
}

gh_status gh_vtable_swap(void *obj, size_t vtable_count, size_t index,
                         void *replacement, void **original_out, void ***new_table_out) {
  if (!obj || !replacement || vtable_count == 0 || index >= vtable_count) return GH_ERR_INVALID_ARG;

  void ***obj_vptr = (void ***)obj;
  void **old_table = *obj_vptr;
  if (!old_table) return GH_ERR_INVALID_ARG;

  void **new_table = (void **)malloc(sizeof(void *) * vtable_count);
  if (!new_table) return GH_ERR_ALLOC;

  memcpy(new_table, old_table, sizeof(void *) * vtable_count);
  if (original_out) *original_out = old_table[index];
  new_table[index] = replacement;

  *obj_vptr = new_table;

  if (new_table_out) *new_table_out = new_table;
  return GH_OK;
}

#endif

/* ---------------- Windows IAT hook ---------------- */

#if GH_ENABLE_IAT
#if GH_PLATFORM_WINDOWS

static gh_status gh_iat_hook_module_internal(HMODULE hmod, const char *import_dll,
                                             const char *func_name, void *replacement, void **original_out) {
  if (!hmod || !import_dll || !func_name || !replacement) return GH_ERR_INVALID_ARG;

  ULONG size = 0;
  PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
      hmod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
  if (!desc) return GH_ERR_NOT_FOUND;

  for (; desc->Name; ++desc) {
    const char *dll = (const char *)((uint8_t *)hmod + desc->Name);
    if (_stricmp(dll, import_dll) != 0) continue;

    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uint8_t *)hmod + desc->FirstThunk);
    PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((uint8_t *)hmod + desc->OriginalFirstThunk);
    for (; orig->u1.AddressOfData; ++orig, ++thunk) {
      if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
      PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((uint8_t *)hmod + orig->u1.AddressOfData);
      if (strcmp((char *)ibn->Name, func_name) != 0) continue;

      if (original_out) *original_out = (void *)thunk->u1.Function;

      int old_prot = 0;
      gh_status st = gh_protect_rwxa(&thunk->u1.Function, sizeof(void *), &old_prot);
      if (st != GH_OK) return st;

      thunk->u1.Function = (uintptr_t)replacement;

      st = gh_restore_prot(&thunk->u1.Function, sizeof(void *), old_prot);
      if (st != GH_OK) return st;

      return GH_OK;
    }
  }

  return GH_ERR_NOT_FOUND;
}

gh_status gh_iat_hook(const char *module_name, const char *import_dll,
                      const char *func_name, void *replacement, void **original_out) {
  HMODULE hmod = module_name ? GetModuleHandleA(module_name) : GetModuleHandleA(NULL);
  if (!hmod) return GH_ERR_NOT_FOUND;
  return gh_iat_hook_module_internal(hmod, import_dll, func_name, replacement, original_out);
}

gh_status gh_iat_hook_module(void *module_base, const char *import_dll,
                             const char *func_name, void *replacement, void **original_out) {
  return gh_iat_hook_module_internal((HMODULE)module_base, import_dll, func_name, replacement, original_out);
}

gh_status gh_iat_hook_all(const char *import_dll, const char *func_name,
                          void *replacement, void **original_out) {
  if (!import_dll || !func_name || !replacement) return GH_ERR_INVALID_ARG;

  HMODULE modules[512];
  DWORD needed = 0;
  if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
    return GH_ERR_STATE;
  }
  size_t count = needed / sizeof(HMODULE);
  for (size_t i = 0; i < count; ++i) {
    gh_status st = gh_iat_hook_module_internal(modules[i], import_dll, func_name, replacement, original_out);
    if (st == GH_OK) return GH_OK;
  }
  return GH_ERR_NOT_FOUND;
}

#if GH_PLATFORM_WINDOWS
gh_status gh_eat_hook(const char *module_name, const char *export_name,
                      void *replacement, void **original_out) {
  if (!export_name || !replacement) return GH_ERR_INVALID_ARG;

  HMODULE hmod = module_name ? GetModuleHandleA(module_name) : GetModuleHandleA(NULL);
  if (!hmod) return GH_ERR_NOT_FOUND;

  ULONG size = 0;
  PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
      hmod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
  if (!exp) return GH_ERR_NOT_FOUND;

  DWORD *names = (DWORD *)((uint8_t *)hmod + exp->AddressOfNames);
  WORD *ords = (WORD *)((uint8_t *)hmod + exp->AddressOfNameOrdinals);
  DWORD *funcs = (DWORD *)((uint8_t *)hmod + exp->AddressOfFunctions);

  for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
    const char *name = (const char *)((uint8_t *)hmod + names[i]);
    if (strcmp(name, export_name) != 0) continue;

    WORD ord = ords[i];
    DWORD *func_rva = &funcs[ord];
    void *orig = (uint8_t *)hmod + *func_rva;
    if (original_out) *original_out = orig;

    uintptr_t base = (uintptr_t)hmod;
    uintptr_t rep = (uintptr_t)replacement;
    DWORD new_rva = 0;
    if (rep >= base && (rep - base) <= 0xFFFFFFFFu) {
      new_rva = (DWORD)(rep - base);
    } else {
      void *stub = VirtualAlloc(NULL, GH_ABS_JMP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      if (!stub) return GH_ERR_ALLOC;
      if (((uintptr_t)stub - base) > 0xFFFFFFFFu) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return GH_ERR_RANGE;
      }
      gh_write_abs_jump(stub, replacement, (unsigned char *)stub);
      new_rva = (DWORD)((uintptr_t)stub - base);
    }

    int old_prot = 0;
    gh_status st = gh_protect_rwxa(func_rva, sizeof(DWORD), &old_prot);
    if (st != GH_OK) return st;

    *func_rva = new_rva;

    st = gh_restore_prot(func_rva, sizeof(DWORD), old_prot);
    if (st != GH_OK) return st;

    return GH_OK;
  }

  return GH_ERR_NOT_FOUND;
}
#endif

void *gh_resolve_export_by_ordinal(void *module_base, uint16_t ordinal) {
  if (!module_base) return NULL;
  HMODULE hmod = (HMODULE)module_base;
  ULONG size = 0;
  PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
      hmod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
  if (!exp) return NULL;

  DWORD base = exp->Base;
  if (ordinal < base || ordinal >= base + exp->NumberOfFunctions) return NULL;

  DWORD *funcs = (DWORD *)((uint8_t *)hmod + exp->AddressOfFunctions);
  DWORD rva = funcs[ordinal - base];
  return (void *)((uint8_t *)hmod + rva);
}

void *gh_resolve_export_forwarder(void *module_base, const char *export_name) {
  if (!module_base || !export_name) return NULL;
  HMODULE hmod = (HMODULE)module_base;
  ULONG size = 0;
  PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
      hmod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
  if (!exp) return NULL;

  DWORD *names = (DWORD *)((uint8_t *)hmod + exp->AddressOfNames);
  WORD *ords = (WORD *)((uint8_t *)hmod + exp->AddressOfNameOrdinals);
  DWORD *funcs = (DWORD *)((uint8_t *)hmod + exp->AddressOfFunctions);

  for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
    const char *name = (const char *)((uint8_t *)hmod + names[i]);
    if (strcmp(name, export_name) != 0) continue;

    WORD ord = ords[i];
    DWORD rva = funcs[ord];
    uint8_t *addr = (uint8_t *)hmod + rva;

    uint8_t *exp_start = (uint8_t *)exp;
    uint8_t *exp_end = exp_start + size;
    if (addr >= exp_start && addr < exp_end) {
      const char *fwd = (const char *)addr;
      const char *dot = strchr(fwd, '.');
      if (!dot) return NULL;

      char dll[128];
      size_t n = (size_t)(dot - fwd);
      if (n >= sizeof(dll)) return NULL;
      memcpy(dll, fwd, n);
      dll[n] = '\0';

      char dllname[160];
      snprintf(dllname, sizeof(dllname), "%s.dll", dll);

      HMODULE fh = GetModuleHandleA(dllname);
      if (!fh) fh = LoadLibraryA(dllname);
      if (!fh) return NULL;

      const char *sym = dot + 1;
      if (sym[0] == '#') {
        uint16_t ord2 = (uint16_t)atoi(sym + 1);
        return gh_resolve_export_by_ordinal(fh, ord2);
      }
      return (void *)GetProcAddress(fh, sym);
    }

    return addr;
  }

  return NULL;
}

gh_status gh_delay_iat_hook(const char *module_name, const char *import_dll,
                            const char *func_name, void *replacement, void **original_out) {
  if (!import_dll || !func_name || !replacement) return GH_ERR_INVALID_ARG;

  HMODULE hmod = module_name ? GetModuleHandleA(module_name) : GetModuleHandleA(NULL);
  if (!hmod) return GH_ERR_NOT_FOUND;

  ULONG size = 0;
  PIMAGE_DELAYLOAD_DESCRIPTOR desc = (PIMAGE_DELAYLOAD_DESCRIPTOR)ImageDirectoryEntryToData(
      hmod, TRUE, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, &size);
  if (!desc) return GH_ERR_NOT_FOUND;

  for (; desc->DllNameRVA; ++desc) {
    const char *dll = (const char *)((uint8_t *)hmod + desc->DllNameRVA);
    if (_stricmp(dll, import_dll) != 0) continue;

    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uint8_t *)hmod + desc->ImportAddressTableRVA);
    PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((uint8_t *)hmod + desc->ImportNameTableRVA);
    for (; orig->u1.AddressOfData; ++orig, ++thunk) {
      if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
      PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((uint8_t *)hmod + orig->u1.AddressOfData);
      if (strcmp((char *)ibn->Name, func_name) != 0) continue;

      if (original_out) *original_out = (void *)thunk->u1.Function;

      int old_prot = 0;
      gh_status st = gh_protect_rwxa(&thunk->u1.Function, sizeof(void *), &old_prot);
      if (st != GH_OK) return st;

      thunk->u1.Function = (uintptr_t)replacement;

      st = gh_restore_prot(&thunk->u1.Function, sizeof(void *), old_prot);
      if (st != GH_OK) return st;

      return GH_OK;
    }
  }

  return GH_ERR_NOT_FOUND;
}

gh_status gh_tls_callback_hook(const char *module_name, size_t index,
                               void *replacement, void **original_out) {
  if (!replacement) return GH_ERR_INVALID_ARG;

  HMODULE hmod = module_name ? GetModuleHandleA(module_name) : GetModuleHandleA(NULL);
  if (!hmod) return GH_ERR_NOT_FOUND;

  ULONG size = 0;
  PIMAGE_TLS_DIRECTORY64 tls = (PIMAGE_TLS_DIRECTORY64)ImageDirectoryEntryToData(
      hmod, TRUE, IMAGE_DIRECTORY_ENTRY_TLS, &size);
  if (!tls || !tls->AddressOfCallBacks) return GH_ERR_NOT_FOUND;

  PVOID *callbacks = (PVOID *)(uintptr_t)tls->AddressOfCallBacks;
  if (!callbacks[index]) return GH_ERR_NOT_FOUND;

  if (original_out) *original_out = callbacks[index];

  int old_prot = 0;
  gh_status st = gh_protect_rwxa(&callbacks[index], sizeof(void *), &old_prot);
  if (st != GH_OK) return st;

  callbacks[index] = replacement;

  st = gh_restore_prot(&callbacks[index], sizeof(void *), old_prot);
  if (st != GH_OK) return st;

  return GH_OK;
}

gh_status gh_eat_hook_module(void *module_base, const char *export_name,
                             void *replacement, void **original_out) {
  HMODULE hmod = (HMODULE)module_base;
  if (!hmod || !export_name || !replacement) return GH_ERR_INVALID_ARG;

  ULONG size = 0;
  PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
      hmod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
  if (!exp) return GH_ERR_NOT_FOUND;

  DWORD *names = (DWORD *)((uint8_t *)hmod + exp->AddressOfNames);
  WORD *ords = (WORD *)((uint8_t *)hmod + exp->AddressOfNameOrdinals);
  DWORD *funcs = (DWORD *)((uint8_t *)hmod + exp->AddressOfFunctions);

  for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
    const char *name = (const char *)((uint8_t *)hmod + names[i]);
    if (strcmp(name, export_name) != 0) continue;

    WORD ord = ords[i];
    DWORD *func_rva = &funcs[ord];
    void *orig = (uint8_t *)hmod + *func_rva;
    if (original_out) *original_out = orig;

    uintptr_t base = (uintptr_t)hmod;
    uintptr_t rep = (uintptr_t)replacement;
    DWORD new_rva = 0;
    if (rep >= base && (rep - base) <= 0xFFFFFFFFu) {
      new_rva = (DWORD)(rep - base);
    } else {
      void *stub = VirtualAlloc(NULL, GH_ABS_JMP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      if (!stub) return GH_ERR_ALLOC;
      if (((uintptr_t)stub - base) > 0xFFFFFFFFu) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return GH_ERR_RANGE;
      }
      gh_write_abs_jump(stub, replacement, (unsigned char *)stub);
      new_rva = (DWORD)((uintptr_t)stub - base);
    }

    int old_prot = 0;
    gh_status st = gh_protect_rwxa(func_rva, sizeof(DWORD), &old_prot);
    if (st != GH_OK) return st;

    *func_rva = new_rva;

    st = gh_restore_prot(func_rva, sizeof(DWORD), old_prot);
    if (st != GH_OK) return st;

    return GH_OK;
  }

  return GH_ERR_NOT_FOUND;
}

#endif
#endif

/* ---------------- POSIX PLT/GOT hook ---------------- */

#if GH_ENABLE_PLT
#if GH_PLATFORM_POSIX && GH_HAS_GNU_SOURCE

typedef struct gh_plt_find_ctx {
  const char *symbol;
  void *replacement;
  void **original_out;
  int found;
} gh_plt_find_ctx;

static int gh_plt_iterate(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size;
  gh_plt_find_ctx *ctx = (gh_plt_find_ctx *)data;

  const Elf64_Phdr *phdr = info->dlpi_phdr;
  const Elf64_Phdr *dyn_phdr = NULL;
  for (int i = 0; i < info->dlpi_phnum; ++i) {
    if (phdr[i].p_type == PT_DYNAMIC) {
      dyn_phdr = &phdr[i];
      break;
    }
  }
  if (!dyn_phdr) return 0;

  Elf64_Dyn *dyn = (Elf64_Dyn *)(info->dlpi_addr + dyn_phdr->p_vaddr);
  Elf64_Sym *symtab = NULL;
  const char *strtab = NULL;
  Elf64_Rela *rela = NULL;
  size_t rela_sz = 0;

  for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_SYMTAB) symtab = (Elf64_Sym *)(info->dlpi_addr + d->d_un.d_ptr);
    if (d->d_tag == DT_STRTAB) strtab = (const char *)(info->dlpi_addr + d->d_un.d_ptr);
    if (d->d_tag == DT_JMPREL) rela = (Elf64_Rela *)(info->dlpi_addr + d->d_un.d_ptr);
    if (d->d_tag == DT_PLTRELSZ) rela_sz = (size_t)d->d_un.d_val;
  }

  if (!symtab || !strtab || !rela || !rela_sz) return 0;

  size_t count = rela_sz / sizeof(Elf64_Rela);
  for (size_t i = 0; i < count; ++i) {
    Elf64_Rela *r = &rela[i];
    size_t sym_idx = ELF64_R_SYM(r->r_info);
    const char *name = strtab + symtab[sym_idx].st_name;
    if (strcmp(name, ctx->symbol) != 0) continue;

    void **got = (void **)(info->dlpi_addr + r->r_offset);
    if (ctx->original_out) *ctx->original_out = *got;

    int old_prot = 0;
    gh_status st = gh_protect_rwxa(got, sizeof(void *), &old_prot);
    if (st != GH_OK) return 1;

    *got = ctx->replacement;

    st = gh_restore_prot(got, sizeof(void *), old_prot);
    if (st != GH_OK) return 1;

    ctx->found = 1;
    return 1;
  }

  return 0;
}

gh_status gh_plt_hook(const char *symbol_name, void *replacement, void **original_out) {
  if (!symbol_name || !replacement) return GH_ERR_INVALID_ARG;

  gh_plt_find_ctx ctx;
  ctx.symbol = symbol_name;
  ctx.replacement = replacement;
  ctx.original_out = original_out;
  ctx.found = 0;

  dl_iterate_phdr(gh_plt_iterate, &ctx);
  return ctx.found ? GH_OK : GH_ERR_NOT_FOUND;
}

#else
gh_status gh_plt_hook(const char *symbol_name, void *replacement, void **original_out) {
  (void)symbol_name; (void)replacement; (void)original_out;
  gh_set_error("plt hook requires _GNU_SOURCE");
  return GH_ERR_UNSUPPORTED;
}
#endif

#endif

/* ---------------- Breakpoint hooks (user-mode) ---------------- */

#if GH_ENABLE_BREAKPOINTS

static gh_breakpoint g_gh_breakpoints[GH_MAX_BREAKPOINTS];

#if GH_PLATFORM_WINDOWS
static PVOID g_gh_veh = NULL;
static DWORD g_gh_tls_idx = TLS_OUT_OF_INDEXES;
#if GH_ENABLE_HW_BREAKPOINTS
static gh_hw_breakpoint g_gh_hw_breakpoints[GH_MAX_HW_BREAKPOINTS];
#endif
static gh_guard_hook g_gh_guard_hooks[GH_MAX_BREAKPOINTS];
static DWORD g_gh_guard_tls_idx = TLS_OUT_OF_INDEXES;

static LONG CALLBACK gh_veh_handler(PEXCEPTION_POINTERS info) {
  if (!info || !info->ExceptionRecord || !info->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;

  if (info->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
    uint8_t *addr = (uint8_t *)info->ExceptionRecord->ExceptionAddress;
    uint8_t *hit = addr - 1;

    for (size_t i = 0; i < GH_MAX_BREAKPOINTS; ++i) {
      if (g_gh_breakpoints[i].enabled && g_gh_breakpoints[i].addr == hit) {
        int old_prot = 0;
        gh_protect_rwxa(hit, 1, &old_prot);
        *hit = g_gh_breakpoints[i].original;
        gh_restore_prot(hit, 1, old_prot);

        info->ContextRecord->Rip = (DWORD64)hit;
        info->ContextRecord->EFlags |= 0x100;
        if (g_gh_tls_idx != TLS_OUT_OF_INDEXES) {
          TlsSetValue(g_gh_tls_idx, hit);
        }

        if (g_gh_breakpoints[i].callback) {
          g_gh_breakpoints[i].callback(hit, g_gh_breakpoints[i].user);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
      }
    }
  }

  if (info->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
    uint8_t *ip = (uint8_t *)info->ContextRecord->Rip;
    for (size_t i = 0; i < GH_MAX_BREAKPOINTS; ++i) {
      if (g_gh_guard_hooks[i].enabled) {
        uint8_t *base = (uint8_t *)g_gh_guard_hooks[i].addr;
        uint8_t *end = base + g_gh_guard_hooks[i].size;
        if (ip >= base && ip < end) {
          if (g_gh_guard_hooks[i].callback) {
            g_gh_guard_hooks[i].callback(ip, g_gh_guard_hooks[i].user);
          }
          info->ContextRecord->EFlags |= 0x100;
          if (g_gh_guard_tls_idx != TLS_OUT_OF_INDEXES) {
            TlsSetValue(g_gh_guard_tls_idx, base);
          }
          return EXCEPTION_CONTINUE_EXECUTION;
        }
      }
    }
  }

  if (info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
    if (g_gh_tls_idx != TLS_OUT_OF_INDEXES) {
      uint8_t *pending = (uint8_t *)TlsGetValue(g_gh_tls_idx);
      if (pending) {
        int old_prot = 0;
        gh_protect_rwxa(pending, 1, &old_prot);
        *pending = 0xCC;
        gh_restore_prot(pending, 1, old_prot);
        TlsSetValue(g_gh_tls_idx, NULL);
        return EXCEPTION_CONTINUE_EXECUTION;
      }
    }
#if GH_PLATFORM_WINDOWS
    if (g_gh_guard_tls_idx != TLS_OUT_OF_INDEXES) {
      uint8_t *pending = (uint8_t *)TlsGetValue(g_gh_guard_tls_idx);
      if (pending) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(pending, &mbi, sizeof(mbi)) == sizeof(mbi)) {
          DWORD oldp = 0;
          VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect | PAGE_GUARD, &oldp);
        }
        TlsSetValue(g_gh_guard_tls_idx, NULL);
        return EXCEPTION_CONTINUE_EXECUTION;
      }
    }
#endif
#if GH_ENABLE_HW_BREAKPOINTS
    DWORD tid = GetCurrentThreadId();
    DWORD64 dr6 = info->ContextRecord->Dr6;
    if (dr6) {
      for (size_t i = 0; i < GH_MAX_HW_BREAKPOINTS; ++i) {
        if (g_gh_hw_breakpoints[i].enabled &&
            g_gh_hw_breakpoints[i].thread == (void *)(uintptr_t)tid) {
          uint8_t *ip = (uint8_t *)info->ContextRecord->Rip;
          if (g_gh_hw_breakpoints[i].addr == ip) {
            if (g_gh_hw_breakpoints[i].callback) {
              g_gh_hw_breakpoints[i].callback(ip, g_gh_hw_breakpoints[i].user);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
          }
        }
      }
    }
#endif
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

static void gh_breakpoints_init_handler(void) {
  if (!g_gh_veh) g_gh_veh = AddVectoredExceptionHandler(1, gh_veh_handler);
  if (g_gh_tls_idx == TLS_OUT_OF_INDEXES) g_gh_tls_idx = TlsAlloc();
  if (g_gh_guard_tls_idx == TLS_OUT_OF_INDEXES) g_gh_guard_tls_idx = TlsAlloc();
}

#elif GH_PLATFORM_POSIX

static int g_gh_sig_installed = 0;
static __thread void *g_gh_pending_bp = NULL;

static void gh_sigtrap_handler(int sig, siginfo_t *si, void *uctx) {
  (void)sig; (void)si;
  ucontext_t *ctx = (ucontext_t *)uctx;
#if defined(__x86_64__) && GH_HAS_GNU_SOURCE && defined(REG_RIP) && defined(REG_EFL)
  greg_t rip = ctx->uc_mcontext.gregs[REG_RIP];
  if (g_gh_pending_bp) {
    uint8_t *pending = (uint8_t *)g_gh_pending_bp;
    int old_prot = 0;
    gh_protect_rwxa(pending, 1, &old_prot);
    *pending = 0xCC;
    gh_restore_prot(pending, 1, old_prot);
    g_gh_pending_bp = NULL;
    return;
  }

  uint8_t *hit = (uint8_t *)(rip - 1);
  for (size_t i = 0; i < GH_MAX_BREAKPOINTS; ++i) {
    if (g_gh_breakpoints[i].enabled && g_gh_breakpoints[i].addr == hit) {
      int old_prot = 0;
      gh_protect_rwxa(hit, 1, &old_prot);
      *hit = g_gh_breakpoints[i].original;
      gh_restore_prot(hit, 1, old_prot);

      ctx->uc_mcontext.gregs[REG_RIP] = (greg_t)hit;
      ctx->uc_mcontext.gregs[REG_EFL] |= 0x100;
      g_gh_pending_bp = hit;

      if (g_gh_breakpoints[i].callback) {
        g_gh_breakpoints[i].callback(hit, g_gh_breakpoints[i].user);
      }
      return;
    }
  }
#endif
}

static void gh_breakpoints_init_handler(void) {
#if GH_HAS_GNU_SOURCE
  if (g_gh_sig_installed) return;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = gh_sigtrap_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigaction(SIGTRAP, &sa, NULL);
  g_gh_sig_installed = 1;
#else
  (void)g_gh_sig_installed;
#endif
}

#endif

static gh_breakpoint *gh_breakpoint_find_slot(void) {
  for (size_t i = 0; i < GH_MAX_BREAKPOINTS; ++i) {
    if (!g_gh_breakpoints[i].enabled) return &g_gh_breakpoints[i];
  }
  return NULL;
}

gh_status gh_breakpoint_add(gh_breakpoint *bp, void *addr, gh_bp_callback cb, void *user) {
  if (!addr || !cb) return GH_ERR_INVALID_ARG;

  gh_breakpoints_init_handler();
#if GH_PLATFORM_POSIX && !GH_HAS_GNU_SOURCE
  gh_set_error("breakpoints require _GNU_SOURCE on Linux");
  (void)bp; (void)user;
  return GH_ERR_UNSUPPORTED;
#endif

  gh_breakpoint *slot = bp ? bp : gh_breakpoint_find_slot();
  if (!slot) return GH_ERR_STATE;

  int old_prot = 0;
  gh_status st = gh_protect_rwxa(addr, 1, &old_prot);
  if (st != GH_OK) return st;

  slot->addr = addr;
  slot->original = *(uint8_t *)addr;
  slot->callback = cb;
  slot->user = user;
  *(uint8_t *)addr = 0xCC;
  slot->enabled = 1;

  st = gh_restore_prot(addr, 1, old_prot);
  if (st != GH_OK) return st;

  return GH_OK;
}

gh_status gh_breakpoint_remove(gh_breakpoint *bp) {
  if (!bp || !bp->enabled || !bp->addr) return GH_ERR_INVALID_ARG;

  int old_prot = 0;
  gh_status st = gh_protect_rwxa(bp->addr, 1, &old_prot);
  if (st != GH_OK) return st;

  *(uint8_t *)bp->addr = bp->original;

  st = gh_restore_prot(bp->addr, 1, old_prot);
  if (st != GH_OK) return st;

  bp->enabled = 0;
  return GH_OK;
}

#if GH_PLATFORM_WINDOWS
static gh_guard_hook *gh_guard_hook_find_slot(void) {
  for (size_t i = 0; i < GH_MAX_BREAKPOINTS; ++i) {
    if (!g_gh_guard_hooks[i].enabled) return &g_gh_guard_hooks[i];
  }
  return NULL;
}

gh_status gh_guard_hook_add(gh_guard_hook *hook, void *addr, size_t size, gh_guard_callback cb, void *user) {
  if (!addr || size == 0 || !cb) return GH_ERR_INVALID_ARG;

  gh_breakpoints_init_handler();

  gh_guard_hook *slot = hook ? hook : gh_guard_hook_find_slot();
  if (!slot) return GH_ERR_STATE;

  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return GH_ERR_STATE;

  DWORD oldp = 0;
  if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect | PAGE_GUARD, &oldp)) {
    return GH_ERR_PROTECT;
  }

  slot->addr = addr;
  slot->size = size;
  slot->callback = cb;
  slot->user = user;
  slot->enabled = 1;
  return GH_OK;
}

gh_status gh_guard_hook_remove(gh_guard_hook *hook) {
  if (!hook || !hook->enabled || !hook->addr) return GH_ERR_INVALID_ARG;

  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(hook->addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return GH_ERR_STATE;

  DWORD oldp = 0;
  VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect & ~PAGE_GUARD, &oldp);
  hook->enabled = 0;
  return GH_OK;
}
#endif

#if GH_ENABLE_HW_BREAKPOINTS
#if GH_PLATFORM_WINDOWS

static gh_hw_breakpoint *gh_hw_breakpoint_find_slot(void) {
  for (size_t i = 0; i < GH_MAX_HW_BREAKPOINTS; ++i) {
    if (!g_gh_hw_breakpoints[i].enabled) return &g_gh_hw_breakpoints[i];
  }
  return NULL;
}

static void gh_hw_set_dr(CONTEXT *ctx, int slot, void *addr) {
  switch (slot) {
    case 0: ctx->Dr0 = (DWORD64)(uintptr_t)addr; break;
    case 1: ctx->Dr1 = (DWORD64)(uintptr_t)addr; break;
    case 2: ctx->Dr2 = (DWORD64)(uintptr_t)addr; break;
    case 3: ctx->Dr3 = (DWORD64)(uintptr_t)addr; break;
    default: break;
  }
}

static void gh_hw_enable_slot(CONTEXT *ctx, int slot, int enable) {
  if (enable) {
    ctx->Dr7 |= (1ull << (slot * 2));
    ctx->Dr7 &= ~(3ull << (16 + slot * 4)); /* exec */
    ctx->Dr7 &= ~(3ull << (18 + slot * 4)); /* len */
  } else {
    ctx->Dr7 &= ~(1ull << (slot * 2));
  }
}

gh_status gh_hw_breakpoint_add(gh_hw_breakpoint *bp, void *addr, void *thread, gh_bp_callback cb, void *user) {
  if (!addr || !thread || !cb) return GH_ERR_INVALID_ARG;

  gh_breakpoints_init_handler();

  gh_hw_breakpoint *slot = bp ? bp : gh_hw_breakpoint_find_slot();
  if (!slot) return GH_ERR_STATE;

  DWORD tid = GetThreadId((HANDLE)thread);
  if (!tid) return GH_ERR_INVALID_ARG;

  int index = (int)(slot - g_gh_hw_breakpoints);
  CONTEXT ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

  SuspendThread((HANDLE)thread);
  if (!GetThreadContext((HANDLE)thread, &ctx)) {
    ResumeThread((HANDLE)thread);
    return GH_ERR_STATE;
  }

  gh_hw_set_dr(&ctx, index, addr);
  gh_hw_enable_slot(&ctx, index, 1);
  ctx.Dr6 = 0;

  if (!SetThreadContext((HANDLE)thread, &ctx)) {
    ResumeThread((HANDLE)thread);
    return GH_ERR_STATE;
  }

  ResumeThread((HANDLE)thread);

  slot->addr = addr;
  slot->thread = (void *)(uintptr_t)tid;
  slot->callback = cb;
  slot->user = user;
  slot->enabled = 1;
  slot->slot = index;

  return GH_OK;
}

gh_status gh_hw_breakpoint_remove(gh_hw_breakpoint *bp) {
  if (!bp || !bp->enabled || !bp->thread) return GH_ERR_INVALID_ARG;

  DWORD tid = (DWORD)(uintptr_t)bp->thread;
  HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
  if (!thread) return GH_ERR_STATE;

  CONTEXT ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

  SuspendThread(thread);
  if (!GetThreadContext(thread, &ctx)) {
    ResumeThread(thread);
    CloseHandle(thread);
    return GH_ERR_STATE;
  }

  gh_hw_set_dr(&ctx, bp->slot, NULL);
  gh_hw_enable_slot(&ctx, bp->slot, 0);
  ctx.Dr6 = 0;

  if (!SetThreadContext(thread, &ctx)) {
    ResumeThread(thread);
    CloseHandle(thread);
    return GH_ERR_STATE;
  }

  ResumeThread(thread);
  CloseHandle(thread);

  bp->enabled = 0;
  return GH_OK;
}

#endif
#endif

void *gh_resolve_symbol(const char *module_name, const char *symbol_name) {
  if (!symbol_name) return NULL;
#if GH_PLATFORM_WINDOWS
  HMODULE hmod = module_name ? GetModuleHandleA(module_name) : GetModuleHandleA(NULL);
  if (!hmod && module_name) hmod = LoadLibraryA(module_name);
  if (!hmod) return NULL;
  return (void *)GetProcAddress(hmod, symbol_name);
#else
  void *handle = RTLD_DEFAULT;
#ifdef RTLD_NOLOAD
  if (module_name) handle = dlopen(module_name, RTLD_LAZY | RTLD_NOLOAD);
#endif
  if (!handle && module_name) handle = dlopen(module_name, RTLD_LAZY);
  if (!handle) handle = RTLD_DEFAULT;
  void *sym = dlsym(handle, symbol_name);
  if (module_name && handle && handle != RTLD_DEFAULT) dlclose(handle);
  return sym;
#endif
}

int gh_enum_modules(gh_module_enum_cb cb, void *user) {
  if (!cb) return 0;
#if GH_PLATFORM_WINDOWS
#if defined(_M_X64)
  PPEB peb = (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86)
  PPEB peb = (PPEB)__readfsdword(0x30);
#else
  PPEB peb = NULL;
#endif
  if (!peb || !peb->Ldr) return 0;

  LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
  for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
    LDR_DATA_TABLE_ENTRY *ent = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    gh_module_info info;
    info.base = ent->DllBase;
    info.size = 0;
    if (ent->DllBase) {
      IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)ent->DllBase;
      if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((uint8_t *)ent->DllBase + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
          info.size = (size_t)nt->OptionalHeader.SizeOfImage;
        }
      }
    }
    info.name = ent->FullDllName.Buffer ? (const char *)ent->FullDllName.Buffer : NULL;
    if (!cb(&info, user)) break;
  }
  return 1;
#else
  (void)user;
  return 0;
#endif
}

int gh_enum_exports(void *module_base, gh_export_enum_cb cb, void *user) {
  if (!module_base || !cb) return 0;
#if GH_PLATFORM_WINDOWS
  HMODULE hmod = (HMODULE)module_base;
  ULONG size = 0;
  PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
      hmod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
  if (!exp) return 0;

  DWORD *names = (DWORD *)((uint8_t *)hmod + exp->AddressOfNames);
  WORD *ords = (WORD *)((uint8_t *)hmod + exp->AddressOfNameOrdinals);
  DWORD *funcs = (DWORD *)((uint8_t *)hmod + exp->AddressOfFunctions);

  uint8_t *exp_start = (uint8_t *)exp;
  uint8_t *exp_end = exp_start + size;

  for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
    const char *name = (const char *)((uint8_t *)hmod + names[i]);
    WORD ord = ords[i];
    DWORD rva = funcs[ord];
    uint8_t *addr = (uint8_t *)hmod + rva;

    gh_export_info info;
    info.name = name;
    info.ordinal = (uint16_t)(exp->Base + ord);
    info.address = addr;
    info.is_forwarder = (addr >= exp_start && addr < exp_end) ? 1 : 0;
    info.forwarder = info.is_forwarder ? (const char *)addr : NULL;

    if (!cb(&info, user)) break;
  }
  return 1;
#else
  (void)user;
  return 0;
#endif
}

typedef struct gh_reentry_slot {
  const gh_reentry_guard *guard;
  int depth;
} gh_reentry_slot;

#if GH_PLATFORM_WINDOWS
static DWORD g_gh_reentry_tls = TLS_OUT_OF_INDEXES;
#else
static __thread gh_reentry_slot g_gh_reentry_slots[8];
#endif

static gh_reentry_slot *gh_reentry_find_slot(const gh_reentry_guard *guard) {
#if GH_PLATFORM_WINDOWS
  if (g_gh_reentry_tls == TLS_OUT_OF_INDEXES) g_gh_reentry_tls = TlsAlloc();
  gh_reentry_slot *slots = (gh_reentry_slot *)TlsGetValue(g_gh_reentry_tls);
  if (!slots) {
    slots = (gh_reentry_slot *)calloc(8, sizeof(gh_reentry_slot));
    TlsSetValue(g_gh_reentry_tls, slots);
  }
#else
  gh_reentry_slot *slots = g_gh_reentry_slots;
#endif

  gh_reentry_slot *empty = NULL;
  for (int i = 0; i < 8; ++i) {
    if (slots[i].guard == guard) return &slots[i];
    if (!slots[i].guard && !empty) empty = &slots[i];
  }
  return empty;
}

int gh_reentry_enter(const gh_reentry_guard *guard) {
  if (!guard) return 1;
  gh_reentry_slot *slot = gh_reentry_find_slot(guard);
  if (!slot) return 0;
  int maxd = guard->max_depth ? guard->max_depth : 1;
  if (slot->depth >= maxd) return 0;
  slot->guard = guard;
  slot->depth += 1;
  return 1;
}

void gh_reentry_leave(const gh_reentry_guard *guard) {
  if (!guard) return;
  gh_reentry_slot *slot = gh_reentry_find_slot(guard);
  if (!slot) return;
  if (slot->depth > 0) slot->depth -= 1;
  if (slot->depth == 0) slot->guard = NULL;
}

#endif

/* ---------------- Thread suspension (Windows built-in) ---------------- */

#if GH_ENABLE_THREAD_SUSPEND
#if GH_PLATFORM_WINDOWS

typedef struct gh_thread_list {
  DWORD *ids;
  HANDLE *handles;
  size_t count;
} gh_thread_list;

static gh_thread_list g_gh_threads;

static void gh_threads_suspend_windows(void) {
  DWORD pid = GetCurrentProcessId();
  DWORD tid = GetCurrentThreadId();

  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return;

  THREADENTRY32 te;
  te.dwSize = sizeof(te);

  size_t cap = 32;
  g_gh_threads.ids = (DWORD *)malloc(sizeof(DWORD) * cap);
  g_gh_threads.handles = (HANDLE *)malloc(sizeof(HANDLE) * cap);
  g_gh_threads.count = 0;

  if (Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID == pid && te.th32ThreadID != tid) {
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (h) {
          if (g_gh_threads.count >= cap) {
            cap *= 2;
            g_gh_threads.ids = (DWORD *)realloc(g_gh_threads.ids, sizeof(DWORD) * cap);
            g_gh_threads.handles = (HANDLE *)realloc(g_gh_threads.handles, sizeof(HANDLE) * cap);
          }
          SuspendThread(h);
          g_gh_threads.ids[g_gh_threads.count] = te.th32ThreadID;
          g_gh_threads.handles[g_gh_threads.count] = h;
          g_gh_threads.count++;
        }
      }
    } while (Thread32Next(snap, &te));
  }

  CloseHandle(snap);
}

static void gh_threads_resume_windows(void) {
  for (size_t i = 0; i < g_gh_threads.count; ++i) {
    ResumeThread(g_gh_threads.handles[i]);
    CloseHandle(g_gh_threads.handles[i]);
  }
  free(g_gh_threads.ids);
  free(g_gh_threads.handles);
  g_gh_threads.ids = NULL;
  g_gh_threads.handles = NULL;
  g_gh_threads.count = 0;
}

#endif
#endif

static void gh_threads_suspend_if_enabled(const gh_hook_options *opts) {
#if GH_ENABLE_THREAD_SUSPEND
  if (opts && opts->suspend_threads) {
    if (g_gh_thread_cbs.suspend_all) {
      g_gh_thread_cbs.suspend_all();
      return;
    }
#if GH_PLATFORM_WINDOWS
    gh_threads_suspend_windows();
#endif
  }
#else
  (void)opts;
#endif
}

static void gh_threads_resume_if_enabled(const gh_hook_options *opts) {
#if GH_ENABLE_THREAD_SUSPEND
  if (opts && opts->suspend_threads) {
    if (g_gh_thread_cbs.resume_all) {
      g_gh_thread_cbs.resume_all();
      return;
    }
#if GH_PLATFORM_WINDOWS
    gh_threads_resume_windows();
#endif
  }
#else
  (void)opts;
#endif
}

#endif /* GELHOOK_IMPLEMENTATION */
