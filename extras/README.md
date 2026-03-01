# Decoder Adapters

This folder contains adapter templates for external disassemblers.

- `decoder_capstone.c` (define `GELHOOK_USE_CAPSTONE` and link Capstone)
- `decoder_zydis.c` (define `GELHOOK_USE_ZYDIS` and link Zydis)

These are templates and require you to map instruction details into `gh_inst`.
