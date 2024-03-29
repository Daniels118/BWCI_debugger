#pragma once

#include <iostream>
#include <vector>
#include <string>

#include <Windows.h>

#define FUNC(NAME, DEF) union {DEF; FARPROC NAME;}

enum Opcodes {
	END, JZ, PUSH, POP, ADD, SYS, SUB, NEG, MUL, DIV,
	MOD, NOT, AND, OR, EQ, NEQ, GEQ, LEQ, GT, LT,
	JMP, SLEEP, EXCEPT, CAST, CALL, ENDEXCEPT, RETEXCEPT, ITEREXCEPT, BRKEXCEPT, SWAP,
	DUP, LINE, REF_AND_OFFSET_PUSH, REF_AND_OFFSET_POP, REF_PUSH, REF_ADD_PUSH, TAN, SIN, COS, ATAN,
	ASIN, ACOS, ATAN2, SQRT, ABS
};

enum DataTypes {
	DT_NONE, DT_INT, DT_FLOAT, DT_COORDS, DT_OBJECT, DT_UNK5, DT_BOOLEAN, DT_VAR
};

constexpr int OPCODES_COUNT = 45;

extern DWORD opcode_attrs[OPCODES_COUNT];

constexpr auto OP_ATTR_ARG = 1;
constexpr auto OP_ATTR_IP = 2 | OP_ATTR_ARG;
constexpr auto OP_ATTR_SCRIPT = 4 | OP_ATTR_ARG;
constexpr auto OP_ATTR_JUMP = 8 | OP_ATTR_ARG | OP_ATTR_IP;
constexpr auto OP_ATTR_FINT = 16;
constexpr auto OP_ATTR_VSTACK = 32;

extern std::vector<std::string> opcode_keywords[OPCODES_COUNT][3];

extern const char* NativeFunctions[];
constexpr auto NATIVE_COUNT = 528;

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

//Instructions to NOP
#define printParseErrorBeepOffset		0xC392
#define MessageBeep_size	8

//DLL statically linked C-runtime functions
#define operator_new_Offset				0x179B6
#define freeOffset						0x17F27
#define _strdupOffset					0x21154

//DLL functions and fields
#define loadGameHeadersOffset			0x2B00
#define createArrayOffset				0x2BF0
#define getVarTypeOffset				0x4740
#define setVarTypeOffset				0x5FB0
#define createVarOffset					0x5690
#define addStringToDataSectionOffset	0x6470
#define doStartScriptOffset				0x6550
#define stopTask0Offset					0x6B80
#define taskExistsOffset				0x68F0
#define readTaskOffset					0x8310
#define lhvmCpuLoopOffset				0x8DA0
#define addReferenceOffset				0x94A0
#define removeReferenceOffset			0x94D0
#define opcode_24_CALL_Offset			0xB4A0
#define getExceptionHandlersCountOffset	0xB920
#define getExceptionHandlerCurrentIpOffset 0xB940
#define parseFileImplOffset				0xEC80

#define headersNotLoadedOffset			0x25618
#define ppCurrentStackOffset			0x2561C
#define opcodesImplOffset				0x25624
#define strNotCompiledOffset			0x25A98
#define	parseFileDefaultInputOffset		0x40E38
#define pInstructionsOffset				0x447DC
#define pInstructionsEndOffset			0x447E0
#define pCurrentTaskExceptStructOffset	0x447E8
#define mainStackOffset					0x447F8
#define pTaskListOffset					0x44908
#define autostartScriptsListOffset		0x44910
#define globalVarsDeclOffset			0x44920
#define pGlobalVarsOffset				0x44938
#define pGlobalVarsEndOffset			0x44940
#define varTypesListOffset				0x44950
#define pScriptListOffset				0x44958
#define pDataSectionOffset				0x44964
#define dataSectionSizeOffset			0x44968
#define ticksCountOffset				0x4496C
#define highestTaskIdOffset				0x44970
#define highestScriptIdOffset			0x44974
#define pScriptInstructionCountOffset	0x4497C
#define ppCurrentTaskOffset				0x44980
#define errorCallbackOffset				0x44994
#define pNativeFunctionsOffset			0x44998
#define taskVarsOffset					0x449B0
#define taskVarsCountOffset				0x459B0
#define parserTraceEnabledOffset		0x45E6C
#define currentFilenameOffset			0x45E78
#define pParseFileInputStreamOffset		0x459D4
#define errorsCountOffset				0x459DC

struct ScriptLibraryRDll {
	union {
		HMODULE hmod;
		uintptr_t base;
	};
	//Exported functions
	FUNC(pAutoStart, int(__cdecl* AutoStart)());	//Start autostart scripts
	FUNC(pCodeSize, int(__cdecl* CodeSize)());
	FUNC(pFindScript, int(__cdecl* FindScript)(int, char* name));
	FUNC(pGetCurrentScriptType, int(__cdecl* GetCurrentScriptType)());
	FUNC(pGetFirstRunningTaskId, int(__cdecl* GetFirstRunningTaskId)(int, char* name));
	FUNC(pGetGlobalVariableValue, float(__cdecl* GetGlobalVariableValue)(int, const char* name));
	FUNC(pGetHighestRunningTask, int(__cdecl* GetHighestRunningTask)());		//Returns the taskId
	FUNC(pGetLocalVariableValue, float(__cdecl* GetLocalVariableValue)(int, const char* scriptName, const char* varName));
	FUNC(pGetNextTask, int(__cdecl* GetNextTask)(int, int taskId));
	FUNC(pGetPreviousTask, int(__cdecl* GetPreviousTask)(int, int taskId));
	FUNC(pGetScriptID, int(__cdecl* GetScriptID)());
	FUNC(pGetScriptInstructionCount, int(__cdecl* GetScriptInstructionCount)());
	FUNC(pGetScriptType, int(__cdecl* GetScriptType)(int, int taskId));
	FUNC(pGetTaskFilename, const char* (__cdecl* GetTaskFilename)(int, int scriptIndex));	//WARNING: here task means script
	FUNC(pGetTaskName, const char* (__cdecl* GetTaskName)(int, int taskId));
	FUNC(pInitialise, int(__cdecl* Initialise)(int a1, LPVOID pNativeFunctions, ErrorCallback errCallback,
												NativeCallCallback nativeCallEnterCallback, NativeCallCallback nativeCallExitCallback,
												int a6, StopTaskCallback stopTaskCallback));
	FUNC(pLineNumber, int(__cdecl* LineNumber)());
	FUNC(pLoadBinary, int(__cdecl* LoadBinary)(int a1, const char* FileName));
	FUNC(pLookIn, int(__cdecl* LookIn)(int, int flag));	//Executes a turn of the task scheduler (should be called each 100 ms)
	FUNC(pLoopGlobalVariables, int(__cdecl* LoopGlobalVariables)(int, int(__cdecl* callback)(char* name, DWORD type, float value)));
	FUNC(pLoopTaskVariables, int(__cdecl* LoopTaskVariables)(int, int(__cdecl* callback)(char* name, DWORD type, float value), int taskId));
	FUNC(pMode, int(__cdecl* Mode)());
	FUNC(pNumTasks, int(__cdecl* NumTasks)());
	FUNC(pOpCode, int(__cdecl* OpCode)());
	FUNC(pOpCodeName, const char* (__cdecl* OpCodeName)(int, int opcode));
	FUNC(pPOP, float(__cdecl* POP)(DWORD* pType));						//The argument can be NULL
	FUNC(pPUSH, Stack* (__cdecl* PUSH)(float value, DWORD type));		//Returns a pointer to the Stack structure
	FUNC(pParseFile, int(__cdecl* ParseFile)(int, const char* FileName, const char* directory));
	FUNC(pParsedFile, int(__cdecl* ParsedFile)(const char* FileName));	//Checks if any script in memory comes from the given file (ignoring path). Returns 0 or 1
	FUNC(pReboot, int(__cdecl* Reboot)());
	FUNC(pRestoreState, int(__cdecl* RestoreState)(int a1, const char* FileName));
	FUNC(pSTRING, const char* (__cdecl* STRING)(int offset));
	FUNC(pSaveBinary, int(__cdecl* SaveBinary)(int a1, const char* FileName));
	FUNC(pSaveState, int(__cdecl* SaveState)(int a1, const char* FileName));
	FUNC(pStartScript, int(__cdecl* StartScript)(int, const char* scriptName, int allowedScriptTypesBitmask));
	FUNC(pStopAllTasks, int(__cdecl* StopAllTasks)());
	FUNC(pStopScripts, int(__cdecl* StopScripts)(int, bool(__cdecl* filterFunction)(const char* scriptName, const char* filename)));
	FUNC(pStopTask, int(__cdecl* StopTask)(int, int taskId));
	FUNC(pStopTasksOfType, int(__cdecl* StopTasksOfType)(int, int scriptTypesBitmask));
	FUNC(pTaskFilename, const char* (__cdecl* TaskFilename)());
	FUNC(pTaskName, const char* (__cdecl* TaskName)());
	FUNC(pTaskNumber, int(__cdecl* TaskNumber)());
	FUNC(pType, int(__cdecl* Type)());
	FUNC(pUnInitialize, int(__cdecl* UnInitialize)());
	FUNC(pValue, int(__cdecl* Value)());
	FUNC(pVersion, int(__cdecl* Version)());
	//Internal functions
	FUNC(pLoadGameHeaders, char(__cdecl* loadGameHeaders)(const char* gamePath));
	FUNC(pCreateArray, int(__cdecl* createArray)(const char* name, int datatype, int size, int global));
	FUNC(pGetVarType, int(__cdecl* getVarType)(int varId));
	FUNC(pSetVarType, void(__cdecl* setVarType)(int vartype, int varId));
	FUNC(pCreateVar, int(__cdecl* createVar)(const char* varName, int datatype, const char* scriptName, int global));
	FUNC(pAddStringToDataSection, size_t(__cdecl* addStringToDataSection)(const char* str));
	FUNC(pDoStartScript, DWORD(__cdecl* doStartScript)(Script* pScript));
	FUNC(pStopTask0, int(__cdecl* stopTask0)(Task* pTask));
	FUNC(pTaskExists, int(__cdecl* taskExists)(int taskNumber));
	FUNC(pReadTask, Script*(__cdecl* readTask)(Task* pTask, void* pStream));
	FUNC(pLhvmCpuLoop, char(__cdecl* lhvmCpuLoop)(int a1));
	FUNC(pAddReference, DWORD(__cdecl* addReference)(DWORD objId));
	FUNC(pRemoveReference, DWORD(__cdecl* removeReference)(DWORD objId));
	FUNC(pOpcode_24_CALL, OpcodeImpl opcode_24_CALL);
	FUNC(pGetExceptionHandlersCount, int(__cdecl* getExceptionHandlersCount)());
	FUNC(pGetExceptionHandlerCurrentIp, int(__cdecl* getExceptionHandlerCurrentIp)(int exceptionHandlerIndex));
	FUNC(pParseFileImpl, int(__cdecl* parseFileImpl)());
	//Statically linked C-runtime functions
	FUNC(pOperator_new, LPVOID(__cdecl* operator_new)(size_t size));
	FUNC(pFree, void(__cdecl* free0)(LPVOID lpMem));
	FUNC(p_strdup, char*(__cdecl* _strdup)(const char* source));
	//Internal fields
	BYTE*				pHeadersNotLoaded;			//0x25618
	Stack**				ppCurrentStack;				//0x2561C
	OpcodeImpl*			opcodesImpl;				//0x25624
	char**				pStrNotCompiled;			//0x25A98
	UFILE*				pParseFileDefaultInput;		//0x40E38
	InstructionVector*	instructions;				//0x447DC
	ExceptStruct**		ppCurrentTaskExceptStruct;	//0x447E8
	Stack*				pMainStack;					//0x447F8
	TaskList*			pTaskList;					//0x44908
	AutostartScriptsList* pAutostartScriptsList;	//0x44910
	VarTypeEntry**		pGlobalVarsDecl;			//0x44920
	VarVector*			globalVars;					//0x44938
	ScriptList*			pScriptList;				//0x44958
	char**				ppDataSection;				//0x44964
	DWORD*				pDataSectionSize;			//0x44968
	DWORD*				pTicksCount;				//0x4496C
	DWORD*				pHighestScriptId;			//0x44974
	DWORD*				pScriptInstructionCount;	//0x4497C
	Task**				ppCurrentTask;				//0x44980
	ErrorCallback*		pErrorCallback;				//0x44994
	TaskVar*			pTaskVars;					//0x449B0
	DWORD*				pTaskVarsCount;				//0x459B0
	DWORD*				pParserTraceEnabled;		//0x45E6C
	char**				pCurrentFilename;			//0x45E78
	UFILE**				ppParseFileInputStream;		//0x459D4
	DWORD**				pErrorsCount;				//0x459DC
};

#undef FUNC
