#pragma once

#define CHL_ASSEMBLER

#include "ScriptLibraryR.h"

void assembler_init();
const char* assemble(Script* script, const int address, const char* str);
