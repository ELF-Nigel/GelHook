/*
  Capstone adapter template for GelHook.
  This file is not built by default. Define GELHOOK_USE_CAPSTONE and link capstone.
*/

#ifdef GELHOOK_USE_CAPSTONE

#include <capstone/capstone.h>
#include "../gelhook.h"

static gh_status gh_capstone_decode(const uint8_t *code, size_t max, gh_inst *out) {
  csh handle = 0;
  cs_insn *insn = NULL;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return GH_ERR_UNSUPPORTED;
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  size_t count = cs_disasm(handle, code, max, 0, 1, &insn);
  if (count == 0) {
    cs_close(&handle);
    return GH_ERR_DECODE;
  }

  memset(out, 0, sizeof(*out));
  out->len = insn[0].size;

  /* TODO: Map Capstone detail fields into gh_inst.
     - RIP-relative info
     - rel branches (call/jmp/jcc)
     - disp/imm offsets
  */

  cs_free(insn, count);
  cs_close(&handle);
  return GH_OK;
}

gh_decoder gh_capstone_decoder(void) {
  gh_decoder d;
  d.decode = gh_capstone_decode;
  return d;
}

#endif
