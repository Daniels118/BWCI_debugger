#define EXCLUDE_EXTERN
#include "ScriptLibraryR.h"

#include <map>
#include <string>
#include <vector>

#include <Windows.h>

#include "utils.h"
#include "logger.h"

#define MessageBeep_size	8

#define SETOFFSET(NAME, OFFSET) *(DWORD*)&ScriptLibraryR::NAME = (DWORD)ScriptLibraryR::hmod + OFFSET;
#define IMPORT(NAME) *(FARPROC*)&ScriptLibraryR::NAME = GetProcAddress(ScriptLibraryR::hmod, #NAME);
#define ALIAS(NEWNAME, NAME) *(uintptr_t*)&ScriptLibraryR::NEWNAME = (uintptr_t)ScriptLibraryR::NAME;

DWORD printParseErrorBeepOffset;

namespace DataTypes {
	const char* datatype_names[8] = {
		"void", "int", "float", "coord", "Object", "Unk5", "bool", "float*"
	};

	const char datatype_chars[8] = {
		'n', 'i', 'f', 'c', 'o', 'u', 'b', 'v'
	};
} // namespace DataTypes

namespace Opcodes {
	int OPCODES_COUNT;
	std::vector<DWORD> opcode_attrs;
	std::vector<std::vector<std::vector<std::string>>> opcode_keywords;

	Opcode END, JZ, PUSH, POP, ADD, SYS, SUB, NEG, MUL, DIV,
		MOD, NOT, AND, OR, EQ, NEQ, GEQ, LEQ, GT, LT,
		JMP, SLEEP, EXCEPT, CAST, CALL, ENDEXCEPT, RETEXCEPT, ITEREXCEPT, BRKEXCEPT, SWAP,
		DUP, LINE, REF_AND_OFFSET_PUSH, REF_AND_OFFSET_POP, REF_PUSH, REF_ADD_PUSH, TAN, SIN, COS, ATAN,
		ASIN, ACOS, ATAN2, SQRT, ABS;

	void initVanilla() {
		END = 0;
		JZ = 1;
		PUSH = 2;
		POP = 3;
		ADD = 4;
		SYS = 5;
		SUB = 6;
		NEG = 7;
		MUL = 8;
		DIV = 9;
		MOD = 10;
		NOT = 11;
		AND = 12;
		OR = 13;
		EQ = 14;
		NEQ = 15;
		GEQ = 16;
		LEQ = 17;
		GT = 18;
		LT = 19;
		JMP = 20;
		SLEEP = 21;
		EXCEPT = 22;
		CAST = 23;
		CALL = 24;
		ENDEXCEPT = 25;
		RETEXCEPT = 26;
		ITEREXCEPT = 27;
		BRKEXCEPT = 28;
		SWAP = 29;
		DUP = -1;
		LINE = 30;
		REF_AND_OFFSET_PUSH = -1;
		REF_AND_OFFSET_POP = -1;
		REF_PUSH = -1;
		REF_ADD_PUSH = -1;
		TAN = -1;
		SIN = -1;
		COS = -1;
		ATAN = -1;
		ASIN = -1;
		ACOS = -1;
		ATAN2 = -1;
		SQRT = -1;
		ABS = -1;
		//
		OPCODES_COUNT = 31;
		//
		opcode_keywords = {
			/*00*/	{{"END"}},
			/*01*/	{{"", "JZ"}, {"", "JZ"}},
			/*02*/	{{"", "PUSHI", "PUSHF", "PUSHC", "PUSHO", "", "PUSHB"}, {"", "PUSHI", "PUSHF", "PUSHC", "PUSHO", "", "PUSHB"}},
			/*03*/	{{"", "POPI", "POPF", "POPC", "POPO", "", "POPB"}, {"", "POPI", "POPF"}},
			/*04*/	{{"", "ADDI", "ADDF", "ADDC"}},
			/*05*/	{{"SYS", "", "SYS2"}},
			/*06*/	{{"", "SUBI", "SUBF", "SUBC"}},
			/*07*/	{{"", "NEGI", "NEGF"}},
			/*08*/	{{"", "MULI", "MULF"}},
			/*09*/	{{"", "DIVI", "DIVF"}},
			/*10*/	{{"", "MODI", "MODF"}},
			/*11*/	{{"", "NOT"}},
			/*12*/	{{"", "AND"}},
			/*13*/	{{"", "OR"}},
			/*14*/	{{"", "", "EQ"}},
			/*15*/	{{"", "", "NEQ"}},
			/*16*/	{{"", "", "GEQ"}},
			/*17*/	{{"", "", "LEQ"}},
			/*18*/	{{"", "", "GT"}},
			/*19*/	{{"", "", "LT"}},
			/*20*/	{{"", "JMP"}, {"", "JMP"}},
			/*21*/	{{"", "", "SLEEP"}},
			/*22*/	{{"", "EXCEPT"}},
			/*23*/	{{"", "CASTI", "CASTF", "CASTC", "CASTO", "", "CASTB"}, {"", "", "ZERO"}},
			/*24*/	{{"", "CALL"}, {"", "START"}},
			/*25*/	{{"", "ENDEXCEPT"}, {"", "FREE"}},
			/*26*/	{{"", "RETEXCEPT"}},	//RETEXCEPT
			/*27*/	{{"", "ITEREXCEPT"}},
			/*28*/	{{"", "BRKEXCEPT"}},
			/*29*/	{{"", "SWAP", "COPYTO"}, {"", "", "COPYFROM"}},
			/*30*/	{{"NOP"}}	//original name: LINE
		};
		//
		opcode_attrs = {
			//TODO
			/* 0*/	0,
			/* 1*/	OP_ATTR_JUMP,
			/* 2*/	OP_ATTR_ARG,
			/* 3*/	OP_ATTR_ARG,
			/* 4*/	OP_ATTR_VSTACK,
			/* 5*/	OP_ATTR_ARG | OP_ATTR_FINT | OP_ATTR_VSTACK,
			/* 6*/	OP_ATTR_VSTACK,
			/* 7*/	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			/*20*/	OP_ATTR_JUMP,
			/*21*/	0,
			/*22*/	OP_ATTR_IP,
			/*23*/	0,
			/*24*/	OP_ATTR_SCRIPT | OP_ATTR_VSTACK,
			/*25*/	0, 0, 0, 0,
			/*29*/	OP_ATTR_ARG | OP_ATTR_FINT | OP_ATTR_VSTACK,
			/*30*/	0	//was OP_ATTR_ARG
		};
	}

	void initCreatureIsle() {
		END = 0;
		JZ = 1;
		PUSH = 2;
		POP = 3;
		ADD = 4;
		SYS = 5;
		SUB = 6;
		NEG = 7;
		MUL = 8;
		DIV = 9;
		MOD = 10;
		NOT = 11;
		AND = 12;
		OR = 13;
		EQ = 14;
		NEQ = 15;
		GEQ = 16;
		LEQ = 17;
		GT = 18;
		LT = 19;
		JMP = 20;
		SLEEP = 21;
		EXCEPT = 22;
		CAST = 23;
		CALL = 24;
		ENDEXCEPT = 25;
		RETEXCEPT = 26;
		ITEREXCEPT = 27;
		BRKEXCEPT = 28;
		SWAP = 29;
		DUP = 30;
		LINE = 31;
		REF_AND_OFFSET_PUSH = 32;
		REF_AND_OFFSET_POP = 33;
		REF_PUSH = 34;
		REF_ADD_PUSH = 35;
		TAN = 36;
		SIN = 37;
		COS = 38;
		ATAN = 39;
		ASIN = 40;
		ACOS = 41;
		ATAN2 = 42;
		SQRT = 43;
		ABS = 44;
		//
		OPCODES_COUNT = 45;
		//
		opcode_keywords = {
			/* 0*/	{{"END"}},
			/* 1*/	{{}, {"", "JZ"}, {"", "JZ"}},
			/* 2*/	{{}, {"", "PUSHI", "PUSHF", "PUSHC", "PUSHO", "", "PUSHB", "PUSHV"}, {"", "", "PUSHF", "", "", "", "", "PUSHV"}},
			/* 3*/	{{}, {"", "POPI", "POPF", "", "POPO"}, {"", "", "POPF"}},
			/* 4*/	{{}, {"", "", "ADDF", "ADDC"}},
			/* 5*/	{{}, {"SYS", "", "SYS2"}},
			/* 6*/	{{}, {"", "", "SUBF", "SUBC"}},
			/* 7*/	{{}, {"", "", "NEG"}},
			/* 8*/	{{}, {"", "", "MUL"}},
			/* 9*/	{{}, {"", "", "DIV"}},
			/*10*/	{{}, {"", "", "MOD"}},
			/*11*/	{{}, {"", "NOT"}},
			/*12*/	{{}, {"", "AND"}},
			/*13*/	{{}, {"", "OR"}},
			/*14*/	{{}, {"", "", "EQ"}},
			/*15*/	{{}, {"", "", "NEQ"}},
			/*16*/	{{}, {"", "", "GEQ"}},
			/*17*/	{{}, {"", "", "LEQ"}},
			/*18*/	{{}, {"", "", "GT"}},
			/*19*/	{{}, {"", "", "LT"}},
			/*20*/	{{}, {"", "JMP"}, {"", "JMP"}},
			/*21*/	{{}, {"", "", "SLEEP"}},
			/*22*/	{{}, {"", "EXCEPT"}},
			/*23*/	{{}, {"", "CASTI", "CASTF", "CASTC", "CASTO", "", "CASTB"}},
			/*24*/	{{}, {"", "CALL"}, {"", "START"}},
			/*25*/	{{}, {"", "ENDEXCEPT"}, {"", "FREE"}},
			/*26*/	{{}, {"", "RETEXCEPT"}},
			/*27*/	{{}, {"", "ITEREXCEPT"}},
			/*28*/	{{}, {"", "BRKEXCEPT"}},
			/*29*/	{{}, {"", "SWAP", "SWAPF"}},
			/*30*/	{{"DUP"}},
			/*31*/	{{}, {}, {"", "", "NOP"}},	//original name: LINE
			/*32*/	{{}, {}, {"", "", "", "", "", "", "", "REF_AND_OFFSET_PUSH"}},
			/*33*/	{{}, {}, {"", "", "REF_AND_OFFSET_POP"}},
			/*34*/	{{}, {"", "", "", "", "", "", "", "REF_PUSH"}, {"", "", "", "", "", "", "", "REF_PUSH2"}},
			/*35*/	{{}, {"", "", "REF_ADD_PUSHF", "", "", "", "", "REF_ADD_PUSHV"}, {"", "", "REF_ADD_PUSHF2", "", "", "", "", "REF_ADD_PUSHV2"}},
			/*36*/	{{"TAN"}},
			/*37*/	{{"SIN"}},
			/*38*/	{{"COS"}},
			/*39*/	{{"ATAN"}},
			/*40*/	{{"ASIN"}},
			/*41*/	{{"ACOS"}},
			/*42*/	{{"ATAN2"}},
			/*43*/	{{"SQRT"}},
			/*44*/	{{"ABS"}}
		};
		//
		opcode_attrs = {
			/* 0*/	0,
			/* 1*/	OP_ATTR_JUMP,
			/* 2*/	OP_ATTR_ARG,
			/* 3*/	OP_ATTR_ARG,
			/* 4*/	OP_ATTR_VSTACK,
			/* 5*/	OP_ATTR_ARG | OP_ATTR_FINT | OP_ATTR_VSTACK,
			/* 6*/	OP_ATTR_VSTACK,
			/* 7*/	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			/*20*/	OP_ATTR_JUMP,
			/*21*/	0,
			/*22*/	OP_ATTR_IP,
			/*23*/	0,
			/*24*/	OP_ATTR_SCRIPT | OP_ATTR_VSTACK,
			/*25*/	0, 0, 0, 0,
			/*29*/	OP_ATTR_ARG | OP_ATTR_FINT | OP_ATTR_VSTACK,
			/*30*/	OP_ATTR_ARG,
			/*31*/	0,	//was OP_ATTR_ARG
			/*32*/	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		};
	}
} // namespace Opcodes

namespace Modes {
	Mode IMMEDIATE;
	Mode REFERENCE;

	Mode BACKWARD;
	Mode FORWARD;

	Mode SYNC;
	Mode ASYNC;

	Mode CAST;
	Mode ZERO;

	Mode END_EXCEPT;
	Mode YIELD;

	Mode COPY_TO;
	Mode COPY_FROM;

	void initVanilla() {
		IMMEDIATE = 0;
		REFERENCE = 1;
		BACKWARD = 0;
		FORWARD = 1;
		SYNC = 0;
		ASYNC = 1;
		CAST = 0;
		ZERO = 1;
		END_EXCEPT = 0;
		YIELD = 1;
		COPY_TO = 0;
		COPY_FROM = 1;
	}

	void initCreatureIsle() {
		IMMEDIATE = 1;
		REFERENCE = 2;
		BACKWARD = 1;
		FORWARD = 2;
		SYNC = 1;
		ASYNC = 2;
		CAST = 1;
		ZERO = 2;
		END_EXCEPT = 1;
		YIELD = 2;
		COPY_TO = 1;
		COPY_FROM = 2;
	}
} // namespace Modes

namespace NativeFunctions {
	int NATIVE_COUNT = 0;
	std::vector<const char*> NativeFunctionNames;
	
	int GET_PROPERTY, GET_POSITION, GAME_TYPE, GAME_SUB_TYPE;

	void initNames(NATIVE_FUNCTION* nativeFunctions) {
		std::map<std::string, int> dups;
		for (int i = 0; i < NATIVE_COUNT; i++) {
			std::string name = nativeFunctions[i].name;
			if (dups.contains(name)) {
				int count = ++dups[name];
				name += std::to_string(count);
			} else {
				dups[name] = 1;
			}
			NativeFunctionNames.push_back(name.c_str());
		}
	}

	void initVanilla() {
		NATIVE_COUNT = 464;
		//
		GET_PROPERTY = 21;
		GET_POSITION = 23;
		GAME_TYPE = 220;
		GAME_SUB_TYPE = 221;
	}

	void initCreatureIsle() {
		NATIVE_COUNT = 528;
		//
		GET_PROPERTY = 18;
		GET_POSITION = 20;
		GAME_TYPE = 213;
		GAME_SUB_TYPE = 214;
	}
}

namespace ObjectTypes {
	std::unordered_map<std::string, std::list<std::string>> TypeProperties;
	std::unordered_map<std::string, std::string> subtypesMap;

	void initCommonTypeProperties() {
		TypeProperties = {
			{"SCRIPT_OBJECT_TYPE_MARKER", {
				"SCRIPT_OBJECT_PROPERTY_TYPE_XPOS", "SCRIPT_OBJECT_PROPERTY_TYPE_YPOS", "SCRIPT_OBJECT_PROPERTY_TYPE_ZPOS"
			}},

		};
	}

	void initCommonSubtypes() {
		subtypesMap = {
			{"SCRIPT_OBJECT_TYPE_ABODE", "ABODE_INFO"},
			{"SCRIPT_OBJECT_TYPE_FEATURE", "FEATURE_INFO"},
			{"SCRIPT_OBJECT_TYPE_VILLAGER", "VILLAGER_INFO"},
			{"SCRIPT_OBJECT_TYPE_VILLAGER_CHILD", "VILLAGER_INFO"},
			{"SCRIPT_OBJECT_TYPE_ANIMAL", "ANIMAL_INFO"},
			{"SCRIPT_OBJECT_TYPE_REWARD", "REWARD_OBJECT_INFO"},
			{"SCRIPT_OBJECT_TYPE_MOBILE_STATIC", "MOBILE_STATIC_INFO"},
			{"SCRIPT_OBJECT_TYPE_DANCE", "DANCE_INFO"},
			{"SCRIPT_OBJECT_TYPE_DEAD_TREE", "TREE_INFO"},
			{"SCRIPT_OBJECT_TYPE_WEATHER_THING", "WEATHER_INFO"},
			{"SCRIPT_OBJECT_TYPE_WORSHIP_SITE", "WORSHIP_SITE_INFO"},
			{"SCRIPT_OBJECT_TYPE_MOBILE_OBJECT", "MOBILE_OBJECT_INFO"},
			{"SCRIPT_OBJECT_TYPE_TREE", "TREE_INFO"},
			{"SCRIPT_OBJECT_TYPE_VORTEX", "VORTEX_TYPE"},
			{"SCRIPT_OBJECT_TYPE_SPELL_SEED", "SPELL_SEED_TYPE"},
			{"SCRIPT_OBJECT_TYPE_FIELD", "FIELD_TYPE_INFO"},
			{"SCRIPT_OBJECT_TYPE_HIGHLIGHT", "ScriptChallengeEnums"},
			{"SCRIPT_OBJECT_TYPE_COMPUTER_PLAYER", "PLAYER_INFO"},
			{"SCRIPT_OBJECT_TYPE_SCAFFOLD", "SCAFFOLD_INFO"},
			{"SCRIPT_OBJECT_TYPE_ANIMATED_STATIC", "ANIMATED_STATIC_INFO"},
			{"SCRIPT_OBJECT_TYPE_FLOWERS", "FLOWERS_INFO"},
			{"SCRIPT_OBJECT_TYPE_ONE_SHOT_SPELL_IN_HAND", "SPELL_SEED_TYPE"},
			{"SCRIPT_OBJECT_TYPE_CREATURE", "CREATURE_TYPE"},
			{"SCRIPT_OBJECT_TYPE_DUMB_CREATURE", "CREATURE_TYPE"},
			{"SCRIPT_OBJECT_TYPE_CREATURE_ISLE_BUILDING", "CREATURE_ISLES_BUILDINGS_INFO"},
			{"SCRIPT_OBJECT_TYPE_ONE_SHOT_SPELL", "SPELL_SEED_TYPE"},
			{"SCRIPT_OBJECT_TYPE_PUZZLE_GAME", "SCRIPT_PUZZLE_GAME_TYPE"},
			{"SCRIPT_OBJECT_TYPE_ROCK", "MOBILE_STATIC_INFO"},
			{"SCRIPT_OBJECT_TYPE_SPELL_DISPENSER", "ABODE_INFO"},
			{"SCRIPT_OBJECT_TYPE_STORE", "POT_INFO"},
			{"SCRIPT_OBJECT_TYPE_TOTEM", "ABODE_INFO"},
			{"SCRIPT_OBJECT_TYPE_CITADEL", "OBJECT_TYPE"},
			{"SCRIPT_OBJECT_TYPE_SPECIAL_FIELD", "FIELD_TYPE_INFO"},
			{"CREATURE_ACTION_LEARNING_TYPE_NORMAL", "CREATURE_ACTION_KNOWN_ABOUT"},
			{"CREATURE_ACTION_LEARNING_TYPE_MAGIC", "MAGIC_TYPE"},
			{"AUDIO_SFX_BANK_TYPE_IN_GAME", "LH_SAMPLE"},
			{"AUDIO_SFX_BANK_TYPE_SCRIPT_SFX", "LH_SCRIPT_SAMPLE"},
			{"AUDIO_SFX_BANK_TYPE_HELP_SPRITES", "HELP_TEXT"},
			{"AUDIO_SFX_BANK_TYPE_SPELL", "LH_SCRIPT_SAMPLE"}
		};
	}

	void initVanilla() {
		initCommonTypeProperties();
		initCommonSubtypes();
	}

	void initCreatureIsle() {
		initCommonTypeProperties();
		initCommonSubtypes();
	}
} // namespace ObjectTypes

namespace ScriptLibraryR {
	HMODULE hmod;

	const char* vartype_names[4] = {
		NULL, "reference", "array", "atomic"
	};

	std::unordered_map<DWORD, std::string> scriptType_names = {
		{1, "script"},
		{2, "help script"},
		{4, "challenge help script"},
		{8, "temple help script"},
		{16, "temple special script"},
		{32, "multiplayer help script"},
	};

	//Exported functions
	int(__cdecl* AutoStart)();	//Start autostart scripts
	int(__cdecl* CodeSize)();
	int(__cdecl* FindScript)(int, char* name);
	int(__cdecl* GetCurrentScriptType)();
	int(__cdecl* GetFirstRunningTaskId)(int, char* name);
	float(__cdecl* GetGlobalVariableValue)(int, const char* name);
	int(__cdecl* GetHighestRunningTask)();		//Returns the taskId
	float(__cdecl* GetLocalVariableValue)(int, const char* scriptName, const char* varName);
	int(__cdecl* GetNextTask)(int, int taskId);
	int(__cdecl* GetPreviousTask)(int, int taskId);
	int(__cdecl* GetScriptID)();
	int(__cdecl* GetScriptInstructionCount)();
	int(__cdecl* GetScriptType)(int, int taskId);
	const char* (__cdecl* GetTaskFilename)(int, int scriptIndex);	//WARNING: here task means script
	const char* (__cdecl* GetTaskName)(int, int taskId);
	int(__cdecl* Initialise)(int a1, NATIVE_FUNCTION* pNativeFunctions, ErrorCallback errCallback,
		NativeCallCallback nativeCallEnterCallback, NativeCallCallback nativeCallExitCallback,
		int a6, StopTaskCallback stopTaskCallback);
	int(__cdecl* LineNumber)();
	int(__cdecl* LoadBinary)(int a1, const char* FileName);
	int(__cdecl* LookIn)(int, int flag);	//Executes a turn of the task scheduler (should be called each 100 ms)
	int(__cdecl* LoopGlobalVariables)(int, int(__cdecl* callback)(char* name, DWORD type, float value));
	int(__cdecl* LoopTaskVariables)(int, int(__cdecl* callback)(char* name, DWORD type, float value), int taskId);
	int(__cdecl* Mode)();
	int(__cdecl* NumTasks)();
	int(__cdecl* OpCode)();
	const char* (__cdecl* OpCodeName)(int, int opcode);
	float(__cdecl* POP)(DWORD* pType);					//The argument can be NULL
	int(__cdecl* POPI)(DWORD* pType);					//The argument can be NULL
	DWORD(__cdecl* POPU)(DWORD* pType);					//The argument can be NULL
	int(__cdecl* PUSH)(float value, DWORD type);
	int(__cdecl* PUSHI)(int value, DWORD type);
	int(__cdecl* PUSHU)(DWORD value, DWORD type);
	int(__cdecl* ParseFile)(int, const char* FileName, const char* directory);
	int(__cdecl* ParsedFile)(const char* FileName);	//Checks if any script in memory comes from the given file (ignoring path). Returns 0 or 1
	int(__cdecl* Reboot)();
	int(__cdecl* RestoreState)(int a1, const char* FileName);
	const char* (__cdecl* STRING)(int offset);
	int(__cdecl* SaveBinary)(int a1, const char* FileName);
	int(__cdecl* SaveState)(int a1, const char* FileName);
	int(__cdecl* StartScript)(int, const char* scriptName, int allowedScriptTypesBitmask);
	int(__cdecl* StopAllTasks)();
	int(__cdecl* StopScripts)(int, bool(__cdecl* filterFunction)(const char* scriptName, const char* filename));
	int(__cdecl* StopTask)(int, int taskId);
	int(__cdecl* StopTasksOfType)(int, int scriptTypesBitmask);
	const char* (__cdecl* TaskFilename)();
	const char* (__cdecl* TaskName)();
	int(__cdecl* TaskNumber)();
	int(__cdecl* Type)();
	int(__cdecl* UnInitialize)();
	int(__cdecl* Value)();
	int(__cdecl* Version)();
	//Internal functions
	char(__cdecl* loadGameHeaders)(const char* gamePath);
	int(__cdecl* createArray)(const char* name, int datatype, int size, int global);
	int(__cdecl* getVarType)(int varId);
	void(__cdecl* setVarType)(int vartype, int varId);
	int(__cdecl* createVar)(const char* varName, int datatype, const char* scriptName, int global);
	size_t(__cdecl* addStringToDataSection)(const char* str);
	DWORD(__cdecl* doStartScript)(Script* pScript);
	int(__cdecl* stopTask0)(Task* pTask);
	int(__cdecl* taskExists)(int taskNumber);
	Script* (__cdecl* readTask)(Task* pTask, void* pStream);
	char(__cdecl* lhvmCpuLoop)(int a1);
	DWORD(__cdecl* addReference)(DWORD objId);
	DWORD(__cdecl* removeReference)(DWORD objId);
	OpcodeImpl opcode_24_CALL;
	int(__cdecl* getExceptionHandlersCount)();
	int(__cdecl* getExceptionHandlerCurrentIp)(int exceptionHandlerIndex);
	int(__cdecl* parseFileImpl)();
	//Statically linked C-runtime functions
	LPVOID(__cdecl* operator_new)(size_t size);
	void(__cdecl* free0)(LPVOID lpMem);
	char* (__cdecl* _strdup)(const char* source);

	//Internal fields
	BYTE* pHeadersNotLoaded;
	Stack** ppCurrentStack;
	OpcodeImpl* opcodesImpl;
	EnumConstantVector* pEnumConstants;
	InstructionVector* instructions;
	ExceptStruct** ppCurrentTaskExceptStruct;
	Stack* pMainStack;
	TaskList* pTaskList;
	AutostartScriptsList* pAutostartScriptsList;
	VarTypeEntry** pGlobalVarsDecl;
	VarVector* globalVars;
	ScriptList* pScriptList;
	char** ppDataSection;
	DWORD* pDataSectionSize;
	DWORD* pTicksCount;
	DWORD* pHighestScriptId;
	DWORD* pScriptInstructionCount;
	Task** ppCurrentTask;
	ErrorCallback* pErrorCallback;
	NATIVE_FUNCTION** ppNativeFunctions;
	TaskVar* pTaskVars;
	DWORD* pTaskVarsCount;
	DWORD* pParserTraceEnabled;
	char** pCurrentFilename;
	UFILE** ppParseFileInputStream;
	DWORD** pErrorsCount;

	void __cdecl dummy_setVarType(int vartype, int varId) {
		if (vartype != VAR_TYPE_ATOMIC) {
			ERR("Only ATOMIC var types are supported");
		}
	}

	int __cdecl dummy_getVarType(int varId) {
		return VAR_TYPE_ATOMIC;
	}

	void initVanillaPointers() {
		//Internal functions
		SETOFFSET(loadGameHeaders, 0x2AC0);
		ScriptLibraryR::createArray = 0;
		ScriptLibraryR::getVarType = dummy_getVarType;
		ScriptLibraryR::setVarType = dummy_setVarType;
		SETOFFSET(createVar, 0x5660);
		SETOFFSET(addStringToDataSection, 0x5EA0);
		SETOFFSET(doStartScript, 0x5F80);
		SETOFFSET(stopTask0, 0x65B0);
		SETOFFSET(taskExists, 0x6320);
		SETOFFSET(readTask, 0x7920);
		SETOFFSET(lhvmCpuLoop, 0x8230);
		SETOFFSET(addReference, 0x8A60);
		SETOFFSET(removeReference, 0x8A90);
		SETOFFSET(opcode_24_CALL, 0x9E40);
		SETOFFSET(getExceptionHandlersCount, 0xA2C0);
		SETOFFSET(getExceptionHandlerCurrentIp, 0xA2E0);
		SETOFFSET(parseFileImpl, 0xD240);
		//Statically linked C-runtime functions
		SETOFFSET(operator_new, 0x14BD6);
		SETOFFSET(free0, 0x15147);
		SETOFFSET(_strdup, 0x1D6B4);
		//Internal fields
		SETOFFSET(pHeadersNotLoaded, 0x21608);
		SETOFFSET(ppCurrentStack, 0x2160C);
		SETOFFSET(opcodesImpl, 0x21610);
		SETOFFSET(pEnumConstants, 0x3BBF0);
		SETOFFSET(instructions, 0x3BC34);
		SETOFFSET(ppCurrentTaskExceptStruct, 0x3BC40);
		SETOFFSET(pMainStack, 0x3BC48);
		SETOFFSET(pTaskList, 0x3BD58);
		SETOFFSET(pAutostartScriptsList, 0x3BD60);
		SETOFFSET(pGlobalVarsDecl, 0x3BD70);
		SETOFFSET(globalVars, 0x3BD88);
		SETOFFSET(pScriptList, 0x3BDA0);
		SETOFFSET(ppDataSection, 0x3BDAC);
		SETOFFSET(pDataSectionSize, 0x3BDB0);
		SETOFFSET(pTicksCount, 0x3BDB4);
		SETOFFSET(pHighestScriptId, 0x3BDBC);
		SETOFFSET(pScriptInstructionCount, 0x3BDC4);
		SETOFFSET(ppCurrentTask, 0x3BDC8);
		SETOFFSET(pErrorCallback, 0x3BDDC);
		SETOFFSET(ppNativeFunctions, 0x3BDE0);
		ScriptLibraryR::pTaskVars = 0;
		ScriptLibraryR::pTaskVarsCount = 0;
		SETOFFSET(pParserTraceEnabled, 0x3C1E4);
		SETOFFSET(pCurrentFilename, 0x3C1F0);
		SETOFFSET(ppParseFileInputStream, 0x3BE10);
		SETOFFSET(pErrorsCount, 0x3BE18);
	}

	void initCreatureIslePointers() {
		//Internal functions
		SETOFFSET(loadGameHeaders, 0x2B00);
		SETOFFSET(createArray, 0x2BF0);
		SETOFFSET(getVarType, 0x4740);
		SETOFFSET(setVarType, 0x5FB0);
		SETOFFSET(createVar, 0x5690);
		SETOFFSET(addStringToDataSection, 0x6470);
		SETOFFSET(doStartScript, 0x6550);
		SETOFFSET(stopTask0, 0x6B80);
		SETOFFSET(taskExists, 0x68F0);
		SETOFFSET(readTask, 0x8310);
		SETOFFSET(lhvmCpuLoop, 0x8DA0);
		SETOFFSET(addReference, 0x94A0);
		SETOFFSET(removeReference, 0x94D0);
		SETOFFSET(opcode_24_CALL, 0xB4A0);
		SETOFFSET(getExceptionHandlersCount, 0xB920);
		SETOFFSET(getExceptionHandlerCurrentIp, 0xB940);
		SETOFFSET(parseFileImpl, 0xEC80);
		//Statically linked C-runtime functions
		SETOFFSET(operator_new, 0x179B6);
		SETOFFSET(free0, 0x17F27);
		SETOFFSET(_strdup, 0x21154);
		//Internal fields
		SETOFFSET(pHeadersNotLoaded, 0x25618);
		SETOFFSET(ppCurrentStack, 0x2561C);
		SETOFFSET(opcodesImpl, 0x25624);
		SETOFFSET(pEnumConstants, 0x44798);
		SETOFFSET(instructions, 0x447DC);
		SETOFFSET(ppCurrentTaskExceptStruct, 0x447E8);
		SETOFFSET(pMainStack, 0x447F8);
		SETOFFSET(pTaskList, 0x44908);
		SETOFFSET(pAutostartScriptsList, 0x44910);
		SETOFFSET(pGlobalVarsDecl, 0x44920);
		SETOFFSET(globalVars, 0x44938);
		SETOFFSET(pScriptList, 0x44958);
		SETOFFSET(ppDataSection, 0x44964);
		SETOFFSET(pDataSectionSize, 0x44968);
		SETOFFSET(pTicksCount, 0x4496C);
		SETOFFSET(pHighestScriptId, 0x44974);
		SETOFFSET(pScriptInstructionCount, 0x4497C);
		SETOFFSET(ppCurrentTask, 0x44980);
		SETOFFSET(pErrorCallback, 0x44994);
		SETOFFSET(ppNativeFunctions, 0x44998);
		SETOFFSET(pTaskVars, 0x449B0);
		SETOFFSET(pTaskVarsCount, 0x459B0);
		SETOFFSET(pParserTraceEnabled, 0x45E6C);
		SETOFFSET(pCurrentFilename, 0x45E78);
		SETOFFSET(ppParseFileInputStream, 0x459D4);
		SETOFFSET(pErrorsCount, 0x459DC);
	}

	void initVanilla() {
		initVanillaPointers();
		Opcodes::initVanilla();
		Modes::initVanilla();
		NativeFunctions::initVanilla();
		ObjectTypes::initVanilla();
		//Instructions to NOP
		printParseErrorBeepOffset = 0xAC42;
	}

	void initCreatureIsle() {
		initCreatureIslePointers();
		Opcodes::initCreatureIsle();
		Modes::initCreatureIsle();
		NativeFunctions::initCreatureIsle();
		ObjectTypes::initCreatureIsle();
		//Instructions to NOP
		printParseErrorBeepOffset = 0xC392;
	}

	void initExportedFunctions() {
		IMPORT(AutoStart);
		IMPORT(CodeSize);
		IMPORT(FindScript);
		IMPORT(GetCurrentScriptType);
		IMPORT(GetFirstRunningTaskId);
		IMPORT(GetGlobalVariableValue);
		IMPORT(GetHighestRunningTask);
		IMPORT(GetLocalVariableValue);
		IMPORT(GetNextTask);
		IMPORT(GetPreviousTask);
		IMPORT(GetScriptID);
		IMPORT(GetScriptInstructionCount);
		IMPORT(GetScriptType);
		IMPORT(GetTaskFilename);
		IMPORT(GetTaskName);
		IMPORT(Initialise);
		IMPORT(LineNumber);
		IMPORT(LoadBinary);
		IMPORT(LookIn);
		IMPORT(LoopGlobalVariables);
		IMPORT(LoopTaskVariables);
		IMPORT(Mode);
		IMPORT(NumTasks);
		IMPORT(OpCode);
		IMPORT(OpCodeName);
		IMPORT(POP);
		ALIAS(POPI, POP);
		ALIAS(POPU, POP);
		IMPORT(PUSH);
		ALIAS(PUSHI, PUSH);
		ALIAS(PUSHU, PUSH);
		IMPORT(ParseFile);
		IMPORT(ParsedFile);
		IMPORT(Reboot);
		IMPORT(RestoreState);
		IMPORT(STRING);
		IMPORT(SaveBinary);
		IMPORT(SaveState);
		IMPORT(StartScript);
		IMPORT(StopAllTasks);
		IMPORT(StopScripts);
		IMPORT(StopTask);
		IMPORT(StopTasksOfType);
		IMPORT(TaskFilename);
		IMPORT(TaskName);
		IMPORT(TaskNumber);
		IMPORT(Type);
		IMPORT(UnInitialize);
		IMPORT(Value);
		IMPORT(Version);
	}

	bool init() {
		TRACE("getting handle to ScriptLibraryR.dll");
		hmod = GetModuleHandleA("ScriptLibraryR.dll");
		if (hmod == NULL) {
			ERR("failed to get handle to ScriptLibraryR.dll");
			return false;
		}
		TRACE("getting address to ScriptLibraryR.dll exported functions");
		initExportedFunctions();
		if (Version == NULL) {
			ERR("failed to get address for proc 'Version'");
			return false;
		}
		TRACE("checking ScriptLibraryR.dll version");
		const int version = Version();
		if (version == 7) {
			printf("Detected ScriptLibraryR version 7 (Vanilla)\n");
			initVanilla();
		} else if (version == 8) {
			printf("Detected ScriptLibraryR version 8 (Creature Isle)\n");
			initCreatureIsle();
		} else {
			ERR("this module can work only with LHVM 7 or 8 (Black & White 1 or Creature Isle), version in use is %d", version);
			return false;
		}
		//NOPs
		TRACE("NOPing undesired instructions");
		if (DWORD r = nop((LPVOID)(hmod + printParseErrorBeepOffset), MessageBeep_size)) {
			WARNING("failed to NOP MessageBeep call, error is %i", r);
		}
		return true;
	}
} // namespace ScriptLibraryR
