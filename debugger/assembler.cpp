#include <string>
#include <vector>
#include <unordered_map>

#include "debug.h"
#include "utils.h"

std::unordered_map<std::string, Instruction> model;
std::unordered_map<std::string, int> nativeMap;

void assembler_init() {
	if (model.empty()) {
		//Build the mapping between mnemonics and sample instructions
		for (int iCode = 0; iCode < OPCODES_COUNT; iCode++) {
			auto& t = opcode_keywords[iCode];
			for (int mode = 0; mode < 3; mode++) {
				auto& t2 = t[mode];
				for (size_t iType = 0; iType < t2.size(); iType++) {
					std::string keyword = t2[iType];
					if (keyword != "" && !model.contains(keyword)) {
						Instruction instr;
						instr.opcode = iCode;
						instr.mode = mode;
						instr.datatype = iType;
						instr.intVal = 0;
						instr.linenumber = 0;
						model[keyword] = instr;
					}
				}
			}
		}
		//Build the mapping between native function names and their IDs
		for (int i = 0; i < NATIVE_COUNT; i++) {
			nativeMap[NativeFunctions[i]] = i;
		}
	}
}

const char* parseIntOrString(char* str, int* pVal) {
	if (str == NULL || *str == 0) return "invalid operand";
	if (*str == '"') {
		char buf[512];
		int l = 0;
		bool escape = false;
		for (str++; *str != 0; str++) {
			char& c = *str;
			if (escape) {
				buf[l++] = c;
				escape = false;
			} else if (c == '\\') {
				escape = true;
			} else if (c == '"') {
				buf[l] = 0;
				if (*(++str) != 0) return "invalid string";
				break;
			} else {
				buf[l++] = c;
			}
		}
		*pVal = getOrDefineString(buf);
		return NULL;
	} else if (isNumber(str)) {
		*pVal = atoi(str);
		return NULL;
	}
	return "invalid operand";
}

const char* assemble(Script* script, const int address, const char* str) {
	if (address < 0 || address >= getTotalInstructions()) return "invalid address";
	char buffer[128];
	strcpy(buffer, str);
	char* keyword = (char*)ltrim(buffer);
	char* operand = (char*)strchr(keyword, ' ');
	if (operand != NULL) {
		*operand = 0;
		operand = (char*)ltrim(operand + 1);
	}
	for (char* pc = keyword; *pc != 0; pc++) {
		*pc = toupper(*pc);
	}
	if (!model.contains(keyword)) return "unknown instruction";
	Instruction instr = model[keyword];	//This is safe since it copies the whole struct
	DWORD attr = opcode_attrs[instr.opcode];
	if ((attr & OP_ATTR_ARG) == OP_ATTR_ARG || (instr.opcode == Opcodes::CAST && instr.mode == 2)) {
		if (instr.opcode == Opcodes::POP) {
			if (operand != NULL) {
				if (instr.datatype == DataTypes::DT_FLOAT) {
					instr.mode = 2;
				}
				char* base = operand;
				int offset = 0;
				char* sOffset = strchr(base, '+');
				if (sOffset != NULL) {
					*(sOffset++) = 0;
					if (!isNumber(sOffset)) {
						return "invalid offset";
					}
					offset = atoi(sOffset);
				}
				int varId = getVarId(script, base);
				if (varId >= 0) {
					instr.intVal = varId + offset;
				} else {
					return "variable not found";
				}
			}
		} else if (instr.opcode == Opcodes::SYS) {
			if (operand == NULL) {
				return "expected native function name";
			} else if (nativeMap.contains(operand)) {
				instr.intVal = nativeMap[operand];
			} else {
				return "unknown native function";
			}
		} else if (instr.opcode == Opcodes::SWAP) {
			if (operand != NULL) {
				if (!isNumber(operand)) {
					return "expected integer value";
				}
				instr.intVal = atoi(operand);
			} else {
				instr.intVal = 0;
			}
		} else {
			if (operand == NULL) return "operand required";
			if ((attr & OP_ATTR_IP) == OP_ATTR_IP) {
				if (!isNumber(operand)) return "expected integer value";
				int ip = script->instructionAddress + atoi(operand);
				instr.intVal = ip;
				if ((attr & OP_ATTR_JUMP) == OP_ATTR_JUMP && ip > address) {
					instr.mode = 2;
				}
			} else if ((attr & OP_ATTR_SCRIPT) == OP_ATTR_SCRIPT) {
				Script* targetScript = getScriptByName(operand);
				if (targetScript == NULL) return "script not found";
				instr.intVal = targetScript->id;
			} else if (operand[0] == '[') {
				operand++;
				char* p = strchr(operand, ']');
				if (p == NULL) return "Expected ']'";
				instr.mode = 2;
				char* base = operand;
				int offset = 0;
				char* sOffset = strchr(base, '+');
				if (sOffset != NULL) {
					*(sOffset++) = 0;
					if (!isNumber(sOffset)) {
						return "invalid offset";
					}
					offset = atoi(sOffset);
				}
				int varId = getVarId(script, base);
				if (varId >= 0) {
					varId += offset;
					if (instr.datatype == DataTypes::DT_VAR) {
						instr.floatVal = (float)varId;
					} else {
						instr.intVal = varId;
					}
				} else {
					return "variable not found";
				}
			} else if (instr.datatype == DataTypes::DT_FLOAT) {
				instr.floatVal = (float)atof(operand);
			} else if (instr.datatype == DataTypes::DT_INT || instr.datatype == DataTypes::DT_NONE) {
				const char* msg = parseIntOrString(operand, &instr.intVal);
				if (msg != NULL) return msg;
			} else if (instr.datatype == DataTypes::DT_BOOLEAN) {
				if (streq(operand, "true")) {
					instr.intVal = 1;
				} else if (streq(operand, "false")) {
					instr.intVal = 0;
				} else {
					return "invalid boolean";
				}
			} else if (instr.datatype == DataTypes::DT_VAR) {
				char* base = operand;
				int offset = 0;
				char* sOffset = strchr(base, '+');
				if (sOffset != NULL) {
					*(sOffset++) = 0;
					if (!isNumber(sOffset)) {
						return "invalid offset";
					}
					offset = atoi(sOffset);
				}
				int varId = getVarId(script, base);
				if (varId >= 0) {
					varId += offset;
					instr.floatVal = (float)varId;
				} else {
					return "variable not found";
				}
			} else {
				return "unexpected error";
			}
		}
	} else if (operand != NULL) {
		return "no operand expected";
	}
	Instruction* instruction = getInstruction(address);
	instruction->opcode = instr.opcode;
	instruction->mode = instr.mode;
	instruction->datatype = instr.datatype;
	instruction->intVal = instr.intVal;
	return NULL;
}
