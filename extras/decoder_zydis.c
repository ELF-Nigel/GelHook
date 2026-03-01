/*
  Zydis adapter template for GelHook.
  This file is not built by default. Define GELHOOK_USE_ZYDIS and link Zydis.
*/

#ifdef GELHOOK_USE_ZYDIS

#include <Zydis/Zydis.h>
#include "../gelhook.h"

static gh_status gh_zydis_decode(const uint8_t *code, size_t max, gh_inst *out) {
  ZydisDecoder decoder;
  ZydisDecodedInstruction instr;

  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
  if (ZYDIS_SUCCESS != ZydisDecoderDecodeBuffer(&decoder, code, max, &instr)) {
    return GH_ERR_DECODE;
  }

  memset(out, 0, sizeof(*out));
  out->len = instr.length;

  /* TODO: Map Zydis detail fields into gh_inst.
     - RIP-relative info
     - rel branches (call/jmp/jcc)
     - disp/imm offsets
  */

  return GH_OK;
}

gh_decoder gh_zydis_decoder(void) {
  gh_decoder d;
  d.decode = gh_zydis_decode;
  return d;
}

#endif
