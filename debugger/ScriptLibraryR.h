#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>

#include <Windows.h>

struct NATIVE_FUNCTION;

namespace DataTypes {
	extern const char* datatype_names[8];

	extern const char datatype_chars[8];

	constexpr auto DT_NONE = 0, DT_INT = 1, DT_FLOAT = 2, DT_COORDS = 3, DT_OBJECT = 4, DT_UNK5 = 5, DT_BOOLEAN = 6, DT_VAR = 7;
} // namespace DataTypes

typedef int Opcode;

namespace Opcodes {
	constexpr int OPCODES_COUNT_MAX = 45;

	constexpr auto OP_ATTR_ARG = 1;
	constexpr auto OP_ATTR_IP = 2 | OP_ATTR_ARG;
	constexpr auto OP_ATTR_SCRIPT = 4 | OP_ATTR_ARG;
	constexpr auto OP_ATTR_JUMP = 8 | OP_ATTR_ARG | OP_ATTR_IP;
	constexpr auto OP_ATTR_FINT = 16;
	constexpr auto OP_ATTR_VSTACK = 32;

#ifndef EXCLUDE_EXTERN
	extern int OPCODES_COUNT;
	extern std::vector<DWORD> opcode_attrs;
	extern std::vector<std::vector<std::vector<std::string>>> opcode_keywords;
	
	extern Opcode END, JZ, PUSH, POP, ADD, SYS, SUB, NEG, MUL, DIV,
		MOD, NOT, AND, OR, EQ, NEQ, GEQ, LEQ, GT, LT,
		JMP, SLEEP, EXCEPT, CAST, CALL, ENDEXCEPT, RETEXCEPT, ITEREXCEPT, BRKEXCEPT, SWAP,
		DUP, LINE, REF_AND_OFFSET_PUSH, REF_AND_OFFSET_POP, REF_PUSH, REF_ADD_PUSH, TAN, SIN, COS, ATAN,
		ASIN, ACOS, ATAN2, SQRT, ABS;

#endif
} // namespace Opcodes

typedef int Mode;

namespace Modes {
#ifndef EXCLUDE_EXTERN
	extern Mode IMMEDIATE;
	extern Mode REFERENCE;

	extern Mode BACKWARD;
	extern Mode FORWARD;

	extern Mode SYNC;
	extern Mode ASYNC;

	extern Mode CAST;
	extern Mode ZERO;

	extern Mode END_EXCEPT;
	extern Mode YIELD;

	extern Mode COPY_TO;
	extern Mode COPY_FROM;
#endif
} // namespace Modes

namespace NativeFunctions {
	constexpr int NATIVE_COUNT_MAX = 528;

#ifndef EXCLUDE_EXTERN
	extern int NATIVE_COUNT;
	extern std::vector<const char*> NativeFunctionNames;
	
	extern int GET_PROPERTY, GET_POSITION, GAME_TYPE, GAME_SUB_TYPE;
#endif

	void initNames(NATIVE_FUNCTION* nativeFunctions);
} // namespace NativeFunctions

namespace ObjectTypes {
#ifndef EXCLUDE_EXTERN
	extern std::unordered_map<std::string, std::list<std::string>> TypeProperties;
	extern std::unordered_map<std::string, std::string> subtypesMap;
#endif
} // namespace ObjectTypes

enum VarTypes {
	VAR_TYPE_REFERENCE = 1,	//?
	VAR_TYPE_ARRAY = 2,
	VAR_TYPE_ATOMIC = 3
};

struct Var {
	DWORD type;
	union {
		FLOAT floatVal;
		int intVal;
		DWORD uintVal;
	};
	const char* name;
};

struct VarType {
	int varId;
	int type;
};

struct VarTypeEntry {
	VarTypeEntry* next;
	VarType* pVarType;
};

struct VarTypeList {
	VarTypeEntry* pFirst;
	size_t count;
};

struct Instruction {
	DWORD opcode;
	DWORD mode;
	DWORD datatype;
	union {
		FLOAT floatVal;
		int intVal;
	};
	DWORD linenumber;
};

struct InstructionVector {
	Instruction* pFirst;
	Instruction* pEnd;
	Instruction* pBufferEnd;
};

struct Stack {
	DWORD count;
	union {
		int intVals[32];
		DWORD uintVals[32];
		FLOAT floatVals[32];
	};
	DWORD types[32];
	DWORD totalPush;
	DWORD totalPop;
};

struct VarDecl {
	char* name;
	char* scriptName;
};

struct VarDeclVector {
	char* lastName;			// 0
	VarDecl** pFirst;		// 4
	VarDecl** pEnd;			// 8
	VarDecl** pBufferEnd;	//12
};

struct Script {
	DWORD unk0;
	char* name;					// 4
	DWORD parameterCount;		// 8
	char* filename;				//12
	VarDeclVector localVars;	//16 (16 bytes)
	DWORD instructionAddress;	//32
	DWORD globalsCount;			//36
	DWORD id;					//40
	DWORD type;					//44
};

struct ScriptEntry {
	ScriptEntry* next;
	Script* script;
};

struct ScriptList {
	ScriptEntry* pFirst;
	size_t count;
};

struct AutostartScriptEntry {
	AutostartScriptEntry* next;
	int scriptId;
};

struct AutostartScriptsList {
	AutostartScriptEntry* first;
	int size;
};

struct VarVector {
	DWORD unk0;			//  0
	Var* pFirst;		//  4
	Var* pEnd;			//  8
	Var* pBufferEnd;	// 12
};

struct IpVector {
	DWORD* pFirst;		//0
	DWORD* pEnd;		//4
	DWORD* pBufferEnd;	//8
};

struct ExceptStruct {
	DWORD instructionAddress;
	IpVector exceptionHandlerIps;
};

struct Task {
	VarVector localVars;				//  0 (16 bytes)
	DWORD scriptID;						// 16
	DWORD taskNumber;					// 20
	DWORD ip;							// 24
	DWORD prevIp;						// 28
	DWORD waitingTask;					// 32
	DWORD globalsCount;					// 36
	Stack stack;						// 40 (268 bytes)
	DWORD currentExceptionHandlerIndex;	//308
	union {
		ExceptStruct exceptStruct;			//312 (16 bytes)
		struct {
			DWORD instructionAddress;		//312
			IpVector exceptionHandlerIps;	//316 (12 bytes)
		};
	};
	DWORD ticks;						//328 - reset by JZ when condition is TRUE
	BYTE  inExceptionHandler;			//332 - break when change
	BYTE  stop;							//333
	BYTE  stopExceptionHandler;			//334 - set by jump forward
	BYTE  sleeping;						//335 - set by SLEEP
	char* name;							//336
	char* filename;						//340
	DWORD type;							//344
};

struct TaskEntry {
	TaskEntry* next;
	Task* task;
};

struct TaskList {
	TaskEntry* pFirst;
	size_t count;
};

struct TaskVar {
	int taskId;
	int varId;
};

typedef DWORD(__cdecl* OpcodeImpl)(Task* pTask, Instruction* pInstr);
typedef int(__cdecl* ErrorCallback)(DWORD severity, const char* msg);
typedef int(__cdecl* NativeCallCallback)(DWORD id);
typedef int(__cdecl* StopTaskCallback)(DWORD taskNumber);
typedef int(__cdecl* NativeFunction)();

struct NATIVE_FUNCTION {
	NativeFunction pointer;
	DWORD stackIn;
	DWORD stackOut;
	DWORD unknown;
	const char name[128];
};

struct StringObj {
	BYTE b[4];
	const char* bytes;
	DWORD len;
	DWORD bufsize;
};

struct StringObjVector {
	StringObj* pFirst;
	StringObj* pEnd;
	StringObj* pBufferEnd;
};

struct IntVector {
	DWORD unk0;
	int* pFirst;
	int* pEnd;
	int* pBufferEnd;
};

struct EnumTableEntry {
	int index;
	DWORD filler;
};

struct EnumTable {
	DWORD unk0;
	EnumTableEntry* pFirst;
	EnumTableEntry* pEnd;
	EnumTableEntry* pBufferEnd;
};

struct EnumConstantVector {
	DWORD unk0;
	StringObjVector names;
	IntVector values;
	EnumTable sorted;
};

struct UFILE {	//Fake type for FILEs handled using the statically linked C-runtime
	char*	_ptr;
	int		_cnt;
	char*	_base;
	int		_flag;
	int		_file;
	int		_charbuf;
	int		_bufsiz;
	char*	_tmpfname;
};

namespace ScriptLibraryR {
#ifndef EXCLUDE_EXTERN
	extern HMODULE hmod;

	extern const char* vartype_names[4];

	extern std::unordered_map<DWORD, std::string> scriptType_names;

	//Exported functions
	extern int(__cdecl* AutoStart)();	//Start autostart scripts
	extern int(__cdecl* CodeSize)();
	extern int(__cdecl* FindScript)(int, char* name);
	extern int(__cdecl* GetCurrentScriptType)();
	extern int(__cdecl* GetFirstRunningTaskId)(int, char* name);
	extern float(__cdecl* GetGlobalVariableValue)(int, const char* name);
	extern int(__cdecl* GetHighestRunningTask)();		//Returns the taskId
	extern float(__cdecl* GetLocalVariableValue)(int, const char* scriptName, const char* varName);
	extern int(__cdecl* GetNextTask)(int, int taskId);
	extern int(__cdecl* GetPreviousTask)(int, int taskId);
	extern int(__cdecl* GetScriptID)();
	extern int(__cdecl* GetScriptInstructionCount)();
	extern int(__cdecl* GetScriptType)(int, int taskId);
	extern const char* (__cdecl* GetTaskFilename)(int, int scriptIndex);	//WARNING: here task means script
	extern const char* (__cdecl* GetTaskName)(int, int taskId);
	extern int(__cdecl* Initialise)(int a1, NATIVE_FUNCTION* pNativeFunctions, ErrorCallback errCallback,
									NativeCallCallback nativeCallEnterCallback, NativeCallCallback nativeCallExitCallback,
									int a6, StopTaskCallback stopTaskCallback);
	extern int(__cdecl* LineNumber)();
	extern int(__cdecl* LoadBinary)(int a1, const char* FileName);
	extern int(__cdecl* LookIn)(int, int flag);	//Executes a turn of the task scheduler (should be called each 100 ms)
	extern int(__cdecl* LoopGlobalVariables)(int, int(__cdecl* callback)(char* name, DWORD type, float value));
	extern int(__cdecl* LoopTaskVariables)(int, int(__cdecl* callback)(char* name, DWORD type, float value), int taskId);
	extern int(__cdecl* Mode)();
	extern int(__cdecl* NumTasks)();
	extern int(__cdecl* OpCode)();
	extern const char* (__cdecl* OpCodeName)(int, int opcode);
	extern float(__cdecl* POP)(DWORD* pType);					//The argument can be NULL
	extern int(__cdecl* POPI)(DWORD* pType);					//The argument can be NULL
	extern DWORD(__cdecl* POPU)(DWORD* pType);					//The argument can be NULL
	extern int(__cdecl* PUSH)(float value, DWORD type);
	extern int(__cdecl* PUSHI)(int value, DWORD type);
	extern int(__cdecl* PUSHU)(DWORD value, DWORD type);
	extern int(__cdecl* ParseFile)(int, const char* FileName, const char* directory);
	extern int(__cdecl* ParsedFile)(const char* FileName);	//Checks if any script in memory comes from the given file (ignoring path). Returns 0 or 1
	extern int(__cdecl* Reboot)();
	extern int(__cdecl* RestoreState)(int a1, const char* FileName);
	extern const char* (__cdecl* STRING)(int offset);
	extern int(__cdecl* SaveBinary)(int a1, const char* FileName);
	extern int(__cdecl* SaveState)(int a1, const char* FileName);
	extern int(__cdecl* StartScript)(int, const char* scriptName, int allowedScriptTypesBitmask);
	extern int(__cdecl* StopAllTasks)();
	extern int(__cdecl* StopScripts)(int, bool(__cdecl* filterFunction)(const char* scriptName, const char* filename));
	extern int(__cdecl* StopTask)(int, int taskId);
	extern int(__cdecl* StopTasksOfType)(int, int scriptTypesBitmask);
	extern const char* (__cdecl* TaskFilename)();
	extern const char* (__cdecl* TaskName)();
	extern int(__cdecl* TaskNumber)();
	extern int(__cdecl* Type)();
	extern int(__cdecl* UnInitialize)();
	extern int(__cdecl* Value)();
	extern int(__cdecl* Version)();
	//Internal functions
	extern char(__cdecl* loadGameHeaders)(const char* gamePath);
	extern int(__cdecl* createArray)(const char* name, int datatype, int size, int global);
	extern int(__cdecl* getVarType)(int varId);
	extern void(__cdecl* setVarType)(int vartype, int varId);
	extern int(__cdecl* createVar)(const char* varName, int datatype, const char* scriptName, int global);
	extern size_t(__cdecl* addStringToDataSection)(const char* str);
	extern DWORD(__cdecl* doStartScript)(Script* pScript);
	extern int(__cdecl* stopTask0)(Task* pTask);
	extern int(__cdecl* taskExists)(int taskNumber);
	extern Script*(__cdecl* readTask)(Task* pTask, void* pStream);
	extern char(__cdecl* lhvmCpuLoop)(int a1);
	extern DWORD(__cdecl* addReference)(DWORD objId);
	extern DWORD(__cdecl* removeReference)(DWORD objId);
	extern OpcodeImpl opcode_24_CALL;
	extern int(__cdecl* getExceptionHandlersCount)();
	extern int(__cdecl* getExceptionHandlerCurrentIp)(int exceptionHandlerIndex);
	extern int(__cdecl* parseFileImpl)();
	//Statically linked C-runtime functions
	extern LPVOID(__cdecl* operator_new)(size_t size);
	extern void(__cdecl* free0)(LPVOID lpMem);
	extern char*(__cdecl* _strdup)(const char* source);

	//Internal fields
	extern BYTE* pHeadersNotLoaded;
	extern Stack** ppCurrentStack;
	extern OpcodeImpl* opcodesImpl;
	extern EnumConstantVector* pEnumConstants;
	extern InstructionVector* instructions;
	extern ExceptStruct** ppCurrentTaskExceptStruct;
	extern Stack* pMainStack;
	extern TaskList* pTaskList;
	extern AutostartScriptsList* pAutostartScriptsList;
	extern VarTypeEntry** pGlobalVarsDecl;
	extern VarVector* globalVars;
	extern ScriptList* pScriptList;
	extern char** ppDataSection;
	extern DWORD* pDataSectionSize;
	extern DWORD* pTicksCount;
	extern DWORD* pHighestScriptId;
	extern DWORD* pScriptInstructionCount;
	extern Task** ppCurrentTask;
	extern ErrorCallback* pErrorCallback;
	extern NATIVE_FUNCTION** ppNativeFunctions;
	extern TaskVar* pTaskVars;
	extern DWORD* pTaskVarsCount;
	extern DWORD* pParserTraceEnabled;
	extern char** pCurrentFilename;
	extern UFILE** ppParseFileInputStream;
	extern DWORD** pErrorsCount;
#endif

	bool init();
};
