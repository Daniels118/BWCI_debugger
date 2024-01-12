#include "dllmain.h"
#include "bwfuncs.h"
#include "ScriptLibraryR.h"
#include "debug.h"
#include "gdb.h"

#include <iostream>

#include <Windows.h>
#include <direct.h>
#include <detours.h>

#include <string>
#include <list>
#include <stack>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>

#include <filesystem>
#include <fstream>

#include "logger.h"
#undef LOG_LEVEL
#undef PAUSE_ON
#define LOG_LEVEL LL_INFO
//#define PAUSE_ON LL_ERROR
#include "logger.h"

ScriptLibraryRDll ScriptLibraryR;

char gamePath[MAX_PATH];
std::set<std::string> sourcePath;
std::unordered_map<std::string, std::vector<std::string>> sources;
std::map<int, Breakpoint*> breakpoints;
std::map<std::string, Watch*> watches;
DWORD lastBreakLine;
Task* steppingThread = NULL;
Task* catchThread = NULL;
BYTE catchSysCalls[NATIVE_COUNT];
DWORD breakFromAddress = 0;
int breakAfterLines = 0;
int breakAfterInstructions = 0;
int stepInMaxDepth = 0;
bool pause = false;

Debugger* debugger;
bool debugging = false;
bool started = false;

std::map<int, Script*> scripts;
std::map<std::string, Script*> scriptsByName;
std::map<int, Task*> threads;
std::unordered_map<int, Task*> tasksParents;
std::unordered_map<int, TaskInfo*> tasksInfo;
Task* caller = NULL;

MemoryManager memoryManager;

std::unordered_map<int, std::unordered_map<std::string, Expression*>> expressionsCache;
size_t unusedExpressionsSize = 0;
constexpr auto MAX_UNUSED_EXPRESSIONS_BYTES = 4096;

ErrorCallback originalErrCallback = NULL;
std::stack<ParserMessages*> parseMessagesTraps;
std::string parseTempFile = "";

int allowedThreadId = 0;

Var resultVar;

int __cdecl errorCallback(DWORD severity, const char* msg);
int getScriptSize(Script* script);
bool relocateCode(int srcIp, int count, int dstIp);
void collectGarbage();


void Fail(const char* a) {
	MessageBoxA(0, a, "Error", MB_TASKMODAL);
	ExitProcess(1);
}

const char* detourErrorCode(LONG err) {
	switch (err) {
		case ERROR_INVALID_BLOCK:
			return "ERROR_INVALID_BLOCK";
		case ERROR_INVALID_HANDLE:
			return "ERROR_INVALID_HANDLE";
		case ERROR_INVALID_OPERATION:
			return "ERROR_INVALID_OPERATION";
		case ERROR_NOT_ENOUGH_MEMORY:
			return "ERROR_NOT_ENOUGH_MEMORY";
	}
	return "unknown";
}

LONG detour(PVOID* ppPointer, PVOID pDetour, const char* name) {
	LONG err = DetourAttach(ppPointer, pDetour);
	if (err) {
		if (err == ERROR_INVALID_HANDLE) {
			if (ppPointer == NULL) {
				ERR("failed to detour %s: ERROR_INVALID_HANDLE %p", name, ppPointer);
			} else {
				ERR("failed to detour %s: ERROR_INVALID_HANDLE %p -> %p", name, ppPointer, *ppPointer);
			}
		} else {
			ERR("failed to detour %s: %s", name, detourErrorCode(err));
		}
	}
	return err;
}

#define DETOUR(NAME, WRAPPER) detour((PVOID*)(&NAME), (PVOID)WRAPPER, #NAME)

void jump(Task* task, int ip) {
	task->ip = ip;
	if (task->inExceptionHandler) {
		task->exceptionHandlerIps.pFirst[task->currentExceptionHandlerIndex] = ip;
	} else {
		task->prevIp = ip;
	}
	Instruction* instr = getInstruction(ip);
	lastBreakLine = instr->linenumber;
}

const char* findStringData(std::string prefix, const char* after) {
	const size_t prefixLen = prefix.length();
	const char* start = *ScriptLibraryR.ppDataSection;
	if (after != NULL) {
		start = after + strlen(after) + 1;
	}
	const char* end = *ScriptLibraryR.ppDataSection + *ScriptLibraryR.pDataSectionSize;
	for (const char* str = start; str < end; str += strlen(str) + 1) {
		if (strncmp(str, prefix.c_str(), prefixLen) == 0) {
			return str;
		}
	}
	return NULL;
}

bool getStoredHash(std::string filename, DWORD* outHash) {
	const char* hashData = findStringData("crc32[" + filename + "]=", NULL);
	if (hashData == NULL) return false;
	const char* sHash = strchr(hashData, '=') + 1;
	*outHash = (DWORD)atoll(sHash);
	return true;
}

int checkFileHash(std::string storedFilename, std::string sourceFilename) {
	DWORD storedHash, fileHash;
	if (!getStoredHash(storedFilename, &storedHash)) {
		debugger->onMessage(1, "Hash for %s not found in compiled CHL, source goodness can't be assured.", storedFilename.c_str());
		return 1;
	}
	if (!crc32file(sourceFilename.c_str(), &fileHash)) {
		debugger->onMessage(3, "Failed to read source file '%s'.", sourceFilename.c_str());
		return -1;
	}
	if (storedHash != fileHash) {
		debugger->onMessage(3, "File %s doesn't match with the stored hash.", sourceFilename.c_str());
		return -2;
	}
	return 0;
}

void setSource(std::string filename, std::vector<std::string> lines) {
	sources[filename] = lines;
}

void unsetSource(std::string filename) {
	sources[filename] = std::vector<std::string>();
}

std::vector<std::string> getSource(std::string filename) {
	if (!sources.contains(filename)) {
		TRACE("searching for %s", filename.c_str());
		bool found = false;
		for (std::string path : sourcePath) {
			TRACE("\tsearching in %s", path.c_str());
			for (const auto& entry : std::filesystem::directory_iterator(path)) {
				TRACE("\t\t%s", entry.path().filename().string().c_str());
				if (entry.path().filename().string() == filename) {
					if (checkFileHash(filename, entry.path().string()) >= 0) {
						DEBUG("file found.");
						sources[filename] = readFile(entry.path());
						found = true;
						break;
					}
				}
			}
			if (found) break;
		}
		if (!found) {
			sources[filename] = std::vector<std::string>();
			debugger->onMessage(3, "File %s not found.", filename.c_str());
		}
	}
	return sources[filename];
}

std::string getSourceLine(std::string filename, int lineno) {
	std::vector<std::string> lines = getSource(filename);
	if (lineno > 0 && lineno <= (int)lines.size()) {
		return lines[lineno - 1];
	} else {
		return "";
	}
}

std::string getCurrentSourceLine(Task* task) {
	Instruction* instruction = getCurrentInstruction(task);
	return getSourceLine(task->filename, instruction->linenumber);
}

int findInstructionIndex(const char* filename, const int linenumber) {
	bool fileFound = false;
	ScriptEntry* scriptEntry = *ScriptLibraryR.pScriptList;
	while (scriptEntry != NULL) {
		Script* script = scriptEntry->script;
		if (streq(script->filename, filename)) {
			fileFound = true;
			const int count = getTotalInstructions();
			for (int ip = script->instructionAddress; ip < count; ip++) {
				Instruction* instruction = &ScriptLibraryR.instructions->pFirst[ip];
				if (instruction->linenumber == linenumber) {
					return ip;
				}
			}
		}
		scriptEntry = scriptEntry->next;
	}
	return fileFound ? -1 : -2;
}

Script* findScriptByIp(DWORD ip) {
	Script* res = NULL;
	DWORD resIp = 0;
	for (ScriptEntry* scriptEntry = *ScriptLibraryR.pScriptList; scriptEntry != NULL; scriptEntry = scriptEntry->next) {
		Script* script = scriptEntry->script;
		if (script->instructionAddress <= ip && script->instructionAddress >= resIp) {
			res = script;
			resIp = script->instructionAddress;
		}
	}
	return res;
}

const char* findFilenameByIp(DWORD ip) {
	Script* script = findScriptByIp(ip);
	if (script == NULL) return NULL;
	return script->filename;
}

int findInstruction(DWORD startIp, DWORD opcode) {
	const int count = getTotalInstructions();
	for (int ip = startIp; ip < count; ip++) {
		Instruction* instr = getInstruction(ip);
		if (instr->opcode == opcode) {
			return ip;
		}
	}
	return -1;
}

void formatVar(Script* script, int id, char* buffer) {
	if (id > (int)script->globalsCount) {
		id -= script->globalsCount + 1;
		StringVector* pVars = &script->localVars;
		char** pName = pVars->pFirst[id];
		if (streq(*pName, "LHVMA")) {
			int index = 0;
			do {
				id--;
				index++;
				pName = pVars->pFirst[id];
			} while (streq("LHVMA", *pName));
			strcpy(buffer, *pName);
			strcat(buffer, "+");
			_itoa(index, &buffer[strlen(buffer)], 10);
		} else {
			strcpy(buffer, *pName);
			id++;
			if (id < pVars->pEnd - pVars->pFirst && streq("LHVMA", *pVars->pFirst[id])) {
				strcat(buffer, "+0");
			}
		}
	} else {
		VarVector* pVars = ScriptLibraryR.globalVars;
		const char* name = pVars->pFirst[id].name;
		if (streq(name, "LHVMA")) {
			int index = 0;
			do {
				id--;
				index++;
				name = pVars->pFirst[id].name;
			} while (streq("LHVMA", name));
			strcpy(buffer, name);
			strcat(buffer, "+");
			_itoa(index, &buffer[strlen(buffer)], 10);
		} else {
			strcpy(buffer, name);
			id++;
			if (id < pVars->pEnd - pVars->pFirst && streq("LHVMA", pVars->pFirst[id].name)) {
				strcat(buffer, "+0");
			}
		}
	}
}

void formatTaskVar(Task* task, int id, char* buffer) {
	VarVector* pVars;
	if (id > (int)task->globalsCount) {
		id -= task->globalsCount + 1;
		pVars = &task->localVars;
	} else {
		pVars = ScriptLibraryR.globalVars;
	}
	const char* name = pVars->pFirst[id].name;
	if (streq(name, "LHVMA")) {
		int index = 0;
		do {
			id--;
			index++;
			name = pVars->pFirst[id].name;
		} while (streq("LHVMA", name));
		strcat(buffer, name);
		strcat(buffer, "+");
		_itoa(index, &buffer[strlen(buffer)], 10);
	} else {
		strcpy(buffer, name);
		id++;
		if (id < pVars->pEnd - pVars->pFirst && streq("LHVMA", pVars->pFirst[id].name)) {
			strcat(buffer, "+0");
		}
	}
}

void formatInstruction(Script* script, Instruction* instr, char* buffer) {
	DWORD opcode = instr->opcode;
	DWORD flags = instr->flags;
	int intVal = instr->intVal;
	strcpy(buffer, opcode_keywords[opcode][instr->flags][instr->datatype].c_str());
	bool hasArg = (opcode_attrs[opcode] & OP_ATTR_ARG) == OP_ATTR_ARG;
	bool popNull = opcode == POP && intVal == 0;
	bool swapZero = opcode == SWAP && intVal == 0;
	bool isZero = opcode == CAST && flags == 2;
	bool isRef = (opcode == PUSH || opcode == POP || opcode == CAST) && flags == 2;
	if (hasArg && !popNull && !swapZero || isZero) {
		strcat(buffer, " ");
		if (opcode == SYS) {
			const char* name = NativeFunctions[intVal];
			strcat(buffer, name);
		} else if (isRef) {
			if (instr->datatype == DT_VAR) {
				intVal = (int)instr->floatVal;
			}
			if (opcode == POP) {
				formatVar(script, intVal, buffer + strlen(buffer));
			} else {
				strcat(buffer, "[");
				formatVar(script, intVal, buffer + strlen(buffer));
				strcat(buffer, "]");
			}
		} else if ((opcode_attrs[opcode] & OP_ATTR_FINT) == OP_ATTR_FINT) {
			_itoa(intVal, &buffer[strlen(buffer)], 10);
		} else {
			switch (instr->datatype) {
				case DT_FLOAT:
					sprintf(&buffer[strlen(buffer)], "%f", instr->floatVal);
					break;
				case DT_BOOLEAN:
					strcat(buffer, intVal ? "true" : "false");
					break;
				case DT_VAR:
					intVal = (int)instr->floatVal;
					formatVar(script, intVal, buffer + strlen(buffer));
					break;
				default:
					_itoa(intVal, &buffer[strlen(buffer)], 10);
			}
		}
	}
}

void formatTaskInstruction(Task* task, Instruction* instr, char* buffer) {
	DWORD opcode = instr->opcode;
	DWORD flags = instr->flags;
	int intVal = instr->intVal;
	strcpy(buffer, opcode_keywords[opcode][instr->flags][instr->datatype].c_str());
	bool hasArg = (opcode_attrs[opcode] & OP_ATTR_ARG) == OP_ATTR_ARG;
	bool popNull = opcode == POP && intVal == 0;
	bool swapZero = opcode == SWAP && intVal == 0;
	bool isZero = opcode == CAST && flags == 2;
	bool isRef = (opcode == PUSH || opcode == POP || opcode == CAST) && flags == 2;
	if (hasArg && !popNull && !swapZero || isZero) {
		strcat(buffer, " ");
		if (opcode == SYS) {
			const char* name = NativeFunctions[intVal];
			strcat(buffer, name);
		} else if (isRef) {
			if (instr->datatype == DT_VAR) {
				intVal = (int)instr->floatVal;
			}
			if (opcode == POP) {
				formatTaskVar(task, intVal, &buffer[strlen(buffer)]);
			} else {
				strcat(buffer, "[");
				formatTaskVar(task, intVal, &buffer[strlen(buffer)]);
				strcat(buffer, "]");
			}
		} else if ((opcode_attrs[opcode] & OP_ATTR_FINT) == OP_ATTR_FINT) {
			_itoa(intVal, &buffer[strlen(buffer)], 10);
		} else {
			switch (instr->datatype) {
				case DT_FLOAT:
					sprintf(&buffer[strlen(buffer)], "%f", instr->floatVal);
					break;
				case DT_BOOLEAN:
					strcat(buffer, intVal ? "true" : "false");
					break;
				case DT_VAR:
					intVal = (int)instr->floatVal;
					formatTaskVar(task, intVal, &buffer[strlen(buffer)]);
					break;
				default:
					_itoa(intVal, &buffer[strlen(buffer)], 10);
			}
		}
	}
}

void formatTaskParameters(Task* task, char* buffer) {
	buffer[0] = 0;
	char* writePos = buffer;
	Script* script = getTaskScript(task);
	if (script->parameterCount > 0) {
		Var* var = &task->localVars.pFirst[0];
		writePos += sprintf(writePos, "%s=%f", var->name, var->floatVal);
		for (UINT i = 1; i < script->parameterCount; i++) {
			var = &task->localVars.pFirst[i];
			writePos += sprintf(writePos, ", %s=%f", var->name, var->floatVal);
		}
	}
}

int parseNameAndIndex(const char* expr, char* outName) {
	strcpy(outName, expr);
	if (char* strIndex = strchr(outName, '[')) {
		*strIndex = 0;
		strIndex++;	//Skip the opening square braket
		for (char* pc = strIndex; *pc != 0; pc++) {
			char& c = *pc;
			if (c == ']') {
				c = 0;			//Remove the closing square bracket
			} else if (c < '0' || c > '9') {
				outName[0] = 0;	//Accept only immediate integer indices
				return -1;
			}
		}
		int index = atoi(strIndex);
		if (index == 0 && !streq(strIndex, "0")) {
			TRACE("index isn't an immediate number");
			return -1;
		}
		TRACE("expression '%s' parsed as variable '%s' and index %i", expr, outName, index);
		return index;
	} else {
		TRACE("expression '%s' parsed as variable '%s'", expr, outName);
		return 0;
	}
}

int getLocalVarId(Script* script, const char* name, int index) {
	int i = 0;
	for (char*** ppVar = script->localVars.pFirst; ppVar < script->localVars.pEnd; ppVar++, i++) {
		if (streq(**ppVar, name)) {
			const int localCount = script->localVars.pEnd - script->localVars.pFirst;
			for (int j = 1; j <= index; j++) {
				if (i + j >= localCount || !streq(*script->localVars.pFirst[i + j], "LHVMA")) {
					debugger->onMessage(3, "Index %i out of bounds for variable '%s'", index, name);
					return INDEX_OUT_OF_BOUNDS;
				}
			}
			return script->globalsCount + 1 + i + index;
		}
	}
	TRACE("Symbol '%s' is not a local variable in script %s", name, script->name);
	return -1;
}

int getGlobalVarId(const char* name, int index) {
	int i = 0;
	for (Var* var = ScriptLibraryR.globalVars->pFirst; var < ScriptLibraryR.globalVars->pEnd; var++, i++) {
		if (streq(var->name, name)) {
			const int globalCount = ScriptLibraryR.globalVars->pEnd - ScriptLibraryR.globalVars->pFirst;
			for (int j = 1; j <= index; j++) {
				if (i + j >= globalCount || !streq(ScriptLibraryR.globalVars->pFirst[i + j].name, "LHVMA")) {
					debugger->onMessage(3, "Index %i out of bounds for variable '%s'", index, name);
					return INDEX_OUT_OF_BOUNDS;
				}
			}
			return i + index;
		}
	}
	TRACE("Symbol '%s' is not a global variable", name);
	return -1;
}

int getVarId(Script* script, const char* name) {
	char name0[80];
	int index = parseNameAndIndex(name, name0);
	if (index < 0) return -1;
	if (script != NULL) {
		int id = getLocalVarId(script, name0, index);
		if (id >= 0) {
			TRACE("variable '%s' resolved with local ID %i", name, id);
			return id;
		}
		if (id < -1) return id;	//pass error codes too (i.e. -2 = index out of bounds)
	}
	int id = getGlobalVarId(name0, index);
	if (script != NULL && id > (int)script->globalsCount) {
		return -1;
	}
	if (id >= 0) {
		TRACE("variable '%s' resolved with global ID %i", name, id);
	}
	return id;
}

Var* getVar(Task* task, const char* name) {
	Var* var = task == NULL ? NULL : getLocalVar(task, name);
	if (var == NULL) {
		var = getGlobalVar(name);
	}
	return var;
}

Var* getVarById(Task* task, int id) {
	if (task != NULL && id > (int)task->globalsCount) {
		const int lIndex = id - 1 - task->globalsCount;
		if (lIndex >= task->localVars.pEnd - task->localVars.pFirst) {
			ERR("invalid local variable id %i in %s", id, task->name);
			return NULL;
		}
		Var* var = task->localVars.pFirst + lIndex;
		TRACE("var ID %i is local var '%s'", id, var->name);
		return var;
	}
	if (id < 0 || id >= getGlobalVarsCount()) {
		ERR("invalid global variable id %i", id);
		return NULL;
	}
	Var* var = ScriptLibraryR.globalVars->pFirst + id;
	TRACE("var ID %i is global var '%s'", id, var->name);
	return var;
}

Var* getBaseAndIndex(Task* task, int id, int* index) {
	Var* var = getVarById(task, id);
	if (var == NULL) return NULL;
	int i = 0;
	while (streq(var->name, "LHVMA")) {
		var--;
		i++;
	}
	*index = i;
	return var;
}

bool varIsGlobal(Var* var) {
	return var >= ScriptLibraryR.globalVars->pFirst && var < ScriptLibraryR.globalVars->pEnd;
}

bool varIsLocal(Var* var, Task* task) {
	return var >= task->localVars.pFirst && var < task->localVars.pEnd;
}

bool varIsArray(Task* task, Var* var) {
	if (streq(var->name, "LHVMA")) return true;
	Var* pEnd = ScriptLibraryR.globalVars->pEnd;
	if (task != NULL && var >= task->localVars.pFirst && var < task->localVars.pEnd) {
		pEnd = task->localVars.pEnd;
	}
	Var* nextVar = var + 1;
	if (nextVar >= pEnd) return false;
	return streq(nextVar->name, "LHVMA");
}

int getVarSize(Task* task, Var* var) {
	Var* pEnd = ScriptLibraryR.globalVars->pEnd;
	if (task != NULL && var >= task->localVars.pFirst && var < task->localVars.pEnd) {
		pEnd = task->localVars.pEnd;
	}
	int size = 1;
	for (var++; var < pEnd && streq(var->name, "LHVMA"); var++) {
		size++;
	}
	return size;
}

int getLocalVarsCount(Task* task) {
	return task->localVars.pEnd - task->localVars.pFirst;
}

Var* getLocalVar(Task* task, const char* name) {
	for (Var* var = task->localVars.pFirst; var < task->localVars.pEnd; var++) {
		if (streq(var->name, name)) {
			return var;
		}
	}
	return NULL;
}

int getGlobalVarsCount() {
	return ScriptLibraryR.globalVars->pEnd - ScriptLibraryR.globalVars->pFirst;
}

Var* getGlobalVar(const char* name) {
	for (Var* var = ScriptLibraryR.globalVars->pFirst; var < ScriptLibraryR.globalVars->pEnd; var++) {
		if (streq(var->name, name)) {
			return var;
		}
	}
	return NULL;
}

int declareGlobalVar(const char* name) {
	const int id = ScriptLibraryR.createVar(name, DT_FLOAT, NULL, TRUE);
	ScriptLibraryR.setVarType(VAR_TYPE_ATOMIC, id);
	return id;
}

Task* getInnermostFrame(Task* task) {
	while (task->waitingTask != 0) {
		task = getTaskById(task->waitingTask);
	}
	return task;
}

int getFrameDepth(Task* task) {
	int depth = 0;
	while (tasksParents.contains(task->taskNumber)) {
		task = tasksParents[task->taskNumber];
		depth++;
	}
	return depth;
}

std::vector<Task*> getBacktrace(Task* task) {
	task = getInnermostFrame(task);
	std::vector<Task*> backtrace;
	backtrace.push_back(task);
	while (tasksParents.contains(task->taskNumber)) {
		task = tasksParents[task->taskNumber];
		backtrace.push_back(task);
	}
	return backtrace;
}

Task* getParentFrame(Task* frame) {
	if (frame == NULL) return NULL;
	if (!tasksParents.contains(frame->taskNumber)) return NULL;
	return tasksParents[frame->taskNumber];
}

Task* getChildFrame(Task* frame) {
	if (frame == NULL) return NULL;
	if (frame->waitingTask == 0) return NULL;
	return getTaskById(frame->waitingTask);
}

std::vector<Task*> getThreads() {
	std::vector<Task*> res;
	res.reserve(threads.size());
	for (auto entry : threads) {
		res.push_back(entry.second);
	}
	return res;
}

Task* getFrame(Task* thread) {
	if (thread->waitingTask) {
		std::map<int, Task*> tasksMap;
		for (TaskEntry* taskEntry = *ScriptLibraryR.pTaskList; taskEntry != NULL; taskEntry = taskEntry->next) {
			Task* t = taskEntry->task;
			tasksMap[t->taskNumber] = t;
		}
		while (thread->waitingTask) {
			thread = tasksMap[thread->waitingTask];
		}
	}
	return thread;
}

Task* getThread(Task* task) {
	if (task == NULL) return NULL;
	while (tasksParents.contains(task->taskNumber)) {
		task = tasksParents[task->taskNumber];
	}
	return task;
}

Task* getTaskById(int taskId) {
	for (TaskEntry* taskEntry = *ScriptLibraryR.pTaskList; taskEntry != NULL; taskEntry = taskEntry->next) {
		Task* t = taskEntry->task;
		if (t->taskNumber == taskId) {
			return t;
		}
	}
	return NULL;
}

int getTotalInstructions() {
	return ScriptLibraryR.instructions->pEnd - ScriptLibraryR.instructions->pFirst;
}

Instruction* getCurrentInstruction(Task* task) {
	return &ScriptLibraryR.instructions->pFirst[task->ip];
}

Instruction* getInstruction(int ip) {
	return &ScriptLibraryR.instructions->pFirst[ip];
}

void initVarTypes() {
	DEBUG("initializing type of global variables");
	int count = ScriptLibraryR.globalVars->pEnd - ScriptLibraryR.globalVars->pFirst;
	for (int id = 0; id < count; id++) {
		Var& var = ScriptLibraryR.globalVars->pFirst[id];
		if (!streq(var.name, "LHVMA")) {
			bool isArray = id < count - 1 && streq(ScriptLibraryR.globalVars->pFirst[id + 1].name, "LHVMA");
			int type = isArray ? VAR_TYPE_ARRAY : VAR_TYPE_ATOMIC;
			ScriptLibraryR.setVarType(type, id);
			TRACE("type of variable %s (%i) set to %s", var.name, id, vartype_names[type]);
		}
	}
}

void cleanup() {
	DEBUG("cleanup");
	sources.clear();
	scripts.clear();
	scriptsByName.clear();
	threads.clear();
	tasksParents.clear();
	for (auto entry : tasksInfo) {
		TaskInfo* taskInfo = entry.second;
		delete taskInfo;
	}
	tasksInfo.clear();
}

void onChlLoaded() {
	DEBUG("CHL loaded");
	breakFromAddress = 0;
	pause = false;
	//
	initVarTypes();
	//
	DEBUG("searching for source directories in CHL");
	const char* source_dirs = findStringData("source_dirs=", NULL);
	if (source_dirs != NULL) {
		char buffer[2048];
		strcpy(buffer, strchr(source_dirs, '=') + 1);
		char* dirs[32];
		const int nDirs = splitArgs(buffer, ';', dirs, 32);
		for (int i = 0; i < nDirs; i++) {
			if (!sourcePath.contains(dirs[i])) {
				sourcePath.insert(dirs[i]);
				printf("Path '%s' added to source path\n", dirs[i]);
			}
		}
	}
}


int ScriptLibraryR_LoadBinary(int a1, char* FileName) {
	DEBUG("LoadBinary(%i, \"%s\")", a1, FileName);
	cleanup();
	int r = ScriptLibraryR.LoadBinary(a1, FileName);
	onChlLoaded();
	return r;
}

int ScriptLibraryR_RestoreState(int a1, char* FileName) {
	DEBUG("RestoreState(%i, \"%s\")", a1, FileName);
	cleanup();
	int r = ScriptLibraryR.RestoreState(a1, FileName);
	onChlLoaded();
	//Build tasks tree
	std::map<int, Task*> parents;
	for (TaskEntry* entry = *ScriptLibraryR.pTaskList; entry != NULL; entry = entry->next) {
		Task* task = entry->task;
		if (task->waitingTask > 0) {
			tasksParents[task->waitingTask] = task;
		}
		TaskInfo* info = new TaskInfo();
		info->exceptionMatched = false;	//TODO
		tasksInfo[task->taskNumber] = info;
	}
	//Build threads list
	for (TaskEntry* entry = *ScriptLibraryR.pTaskList; entry != NULL; entry = entry->next) {
		Task* task = entry->task;
		if (!tasksParents.contains(task->taskNumber)) {
			threads[task->taskNumber] = task;
			debugger->threadResumed(task);
		}
	}
	//
	return r;
}

int ScriptLibraryR_StartScript(int a1, char* scriptName, int allowedScriptTypesBitmask) {
	DEBUG("StartScript(%i, \"%s\", %X)", a1, scriptName, allowedScriptTypesBitmask);
	int r = ScriptLibraryR.StartScript(a1, scriptName, allowedScriptTypesBitmask);
	return r;
}

void debugger_execute_pre(Task* task) {
	Instruction* instruction = getCurrentInstruction(task);
	if (pause) {
		pause = false;
		breakAfterInstructions = 0;
		breakAfterLines = 0;
		lastBreakLine = instruction->linenumber;
		debugger->onPauseBeforeLine(task);
	} else if (breakpoints.contains(task->ip)) {
		Breakpoint* breakpoint = breakpoints[task->ip];
		if (breakpoint->isEnabled() && !breakpoint->disabledByTrigger
			&& (breakpoint->thread == NULL || breakpoint->thread == getThread(task))) {
			bool hit = true;
			if (breakpoint->getCondition() != NULL) {
				hit = evalExpression(task, breakpoint->getCondition())->floatVal != 0.0;
				if (hit) {
					DEBUG("breakpoint condition matched at %s:%i", breakpoint->filename.c_str(), breakpoint->lineno);
				} else {
					TRACE("breakpoint condition not matched at %s:%i", breakpoint->filename.c_str(), breakpoint->lineno);
				}
			}
			if (hit) {
				breakpoint->hits++;
				if (breakpoint->targetHitCount == 0 || breakpoint->targetHitCount == breakpoint->hits) {
					lastBreakLine = instruction->linenumber;
					if (breakpoint->targetHitCount) {
						breakpoint->setEnabled(false);
					}
					debugger->breakpointHit(task, breakpoint);
				}
			}
		}
	} else if (breakFromAddress < 0x7FFFFFFF) {
		if (task->ip >= breakFromAddress && (steppingThread == NULL || getThread(task) == steppingThread)
			&& (!task->inExceptionHandler || tasksInfo[task->taskNumber]->exceptionMatched)) {
			if (getFrameDepth(task) <= stepInMaxDepth) {
				breakFromAddress = 0x7FFFFFFF;
				if (breakAfterLines == 0) {
					lastBreakLine = instruction->linenumber;
					debugger->onPauseBeforeLine(task);
				}
			}
		}
	} else if (breakAfterInstructions > 0 && (steppingThread == NULL || getThread(task) == steppingThread)
			&& (!task->inExceptionHandler || tasksInfo[task->taskNumber]->exceptionMatched)) {
		if (getFrameDepth(task) <= stepInMaxDepth) {
			if (--breakAfterInstructions == 0) {
				lastBreakLine = instruction->linenumber;
				debugger->onPauseBeforeInstruction(task);
			} else {
				debugger->beforeInstruction(task);
			}
		}
	} else if (breakAfterLines > 0 && (steppingThread == NULL || getThread(task) == steppingThread)
		&& (!task->inExceptionHandler || tasksInfo[task->taskNumber]->exceptionMatched)) {
		if (instruction->linenumber != lastBreakLine /*|| instruction->opcode == JMP*/ || instruction->opcode == JZ) {
			if (getFrameDepth(task) <= stepInMaxDepth) {
				if (--breakAfterLines == 0) {
					lastBreakLine = instruction->linenumber;
					debugger->onPauseBeforeLine(task);
				} else {
					debugger->beforeLine(task);
				}
			}
		}
	} else if (instruction->opcode == SYS
			&& instruction->intVal >= 0 && instruction->intVal < NATIVE_COUNT && catchSysCalls[instruction->intVal] == ENABLED) {
		debugger->onCatchpoint(task, EV_SYSCALL);
	}
}

void debugger_execute_post(Task* task) {
	bool exception = false;
	Instruction* instruction = getCurrentInstruction(task);
	if (task->inExceptionHandler) {
		if (instruction->opcode == JZ && !tasksInfo[task->taskNumber]->exceptionMatched) {
			bool cond = task->stack.intVals[task->stack.count] != 0;	//The condition has been popped but the value is still on the stack
			if (cond) {
				if (catchThread != NULL || getThread(task) == catchThread) {
					tasksInfo[task->taskNumber]->exceptionMatched = true;
					exception = true;
				}
			}
		} else if (instruction->opcode == ITEREXCEPT || instruction->opcode == ENDEXCEPT || instruction->opcode == BRKEXCEPT) {
			tasksInfo[task->taskNumber]->exceptionMatched = false;
		}
	}
	//
	std::list<Watch*> watchesMatched;
	for (auto entry : watches) {
		Watch* watch = entry.second;
		if (watch->isEnabled()) {
			watch->oldValue = watch->newValue;
			watch->matched = false;
			if (watch->getExpression()->script == NULL || watch->getExpression()->script->id == task->scriptID) {
				Var* pNewVal = evalExpression(task, watch->getExpression());
				if (pNewVal != NULL) {
					float newVal = pNewVal->floatVal;
					if (newVal != watch->oldValue) {
						watch->newValue = newVal;
						watch->matched = true;
						watchesMatched.push_back(watch);
					}
				}
			}
		}
	}
	//
	if (exception || !watchesMatched.empty()) {
		lastBreakLine = instruction->linenumber;
		debugger->onException(task, exception, watchesMatched);
	} else if (instruction->opcode == SYS && catchSysCalls[instruction->intVal] == ENABLED) {
		debugger->onCatchpoint(task, EV_SYSCALL_RET);
	}
}

char __cdecl ScriptLibraryR_lhvmCpuLoop(Task* task) {	//at 0x8DA0
	Task*& currentTask = *ScriptLibraryR.ppCurrentTask;
	DWORD& scriptInstructionCount = *ScriptLibraryR.pScriptInstructionCount;
	//
	if (allowedThreadId != 0 && getThread(task)->taskNumber != allowedThreadId) {
		return 0;
	}
	//
	char inExceptionHandler = task->inExceptionHandler;
	task->stopExceptionHandler = 0;
	if (!task->waitingTask) {
		do {
			currentTask = task;
			debugger_execute_pre(task);		//hook in
			if (allowedThreadId != 0 && getThread(task)->taskNumber != allowedThreadId) {
				break;
			}
			++scriptInstructionCount;
			Instruction& instruction = ScriptLibraryR.instructions->pFirst[task->ip];
			OpcodeImpl opcodeImpl = ScriptLibraryR.opcodesImpl[instruction.opcode];
			opcodeImpl(currentTask, &instruction);
			debugger_execute_post(task);	//hook out
			if (task->stop)
				break;
			if (task->stopExceptionHandler)
				break;
			if (task->waitingTask)
				break;
			if (task->inExceptionHandler != inExceptionHandler)
				break;
			++task->ip;
			currentTask = 0;
		} while (!task->waitingTask);
	}
	currentTask = 0;
	return 0;
}

Script* getScriptById(int scriptId) {
	if (!scripts.contains(scriptId)) {
		for (ScriptEntry* scriptEntry = *ScriptLibraryR.pScriptList; scriptEntry != NULL; scriptEntry = scriptEntry->next) {
			Script* script = scriptEntry->script;
			if (script->id == scriptId) {
				scripts[scriptId] = script;
				return script;
			}
		}
	}
	return scripts[scriptId];
}

Script* getScriptByName(std::string name) {
	if (!scriptsByName.contains(name)) {
		for (ScriptEntry* scriptEntry = *ScriptLibraryR.pScriptList; scriptEntry != NULL; scriptEntry = scriptEntry->next) {
			Script* script = scriptEntry->script;
			if (script->name == name) {
				scriptsByName[name] = script;
				return script;
			}
		}
	}
	return scriptsByName[name];
}

Script* getTaskScript(Task* task) {
	if (task == NULL) return NULL;
	return getScriptById(task->scriptID);
}

bool isScriptRunning(int scriptId) {
	for (TaskEntry* entry = *ScriptLibraryR.pTaskList; entry != NULL; entry = entry->next) {
		Task* task = entry->task;
		if (task->scriptID == scriptId) {
			return true;
		}
	}
	return false;
}

void deleteScript0(Script* script, bool releaseCode) {
	if (releaseCode) {
		const int scriptSize = getScriptSize(script);
		DEBUG("marking instructions %i -> %i as free space", script->instructionAddress, script->instructionAddress + scriptSize);
		memoryManager.addFreeSpace(script->instructionAddress, scriptSize);
	}
	if (script->localVars.pFirst != NULL) {
		ScriptLibraryR.free0(script->localVars.pFirst);
	}
	ScriptLibraryR.free0(script);
}

bool deleteScriptByName(const char* name) {
	ScriptEntry* prevEntry = NULL;
	for (ScriptEntry* entry = *ScriptLibraryR.pScriptList; entry != NULL; entry = entry->next) {
		Script* script = entry->script;
		if (streq(script->name, name)) {
			if (isScriptRunning(script->id)) {
				debugger->onMessage(3, "Cannot delete script '%s' because it is being executed.", script->name);
				return false;
			}
			debugger->onMessage(1, "Script '%s' deleted.", script->name);
			deleteScript0(script, true);
			ScriptLibraryR.free0(entry);
			if (prevEntry == NULL) {
				*ScriptLibraryR.pScriptList = entry->next;
			} else {
				prevEntry->next = entry->next;
			}
			scriptsByName.erase(name);
			return true;
		}
		prevEntry = entry;
	}
	debugger->onMessage(2, "Script '%s' not found.", name);
	return false;
}

int getScriptSize(Script* script) {
	int endIp = findInstruction(script->instructionAddress, END);
	if (endIp < 0) return 0;
	return endIp - script->instructionAddress + 1;
}

bool relocateCode(int srcIp, int count, int dstIp) {
	if (dstIp >= srcIp) {
		ERR("code can be moved only towards lower addresses");
		return false;
	}
	int offset = dstIp - srcIp;
	Instruction* src = getInstruction(srcIp);
	Instruction* dst = getInstruction(dstIp);
	for (int i = 0; i < count; i++, src++, dst++) {
		*dst = *src;
		if (dst->opcode == END) break;
		DWORD attr = opcode_attrs[dst->opcode];
		if ((attr & OP_ATTR_IP) == OP_ATTR_IP) {
			dst->intVal += offset;
		}
	}
	return true;
}

bool relocateScript(Script* script, int dstIp) {
	if (isScriptRunning(script->id)) {
		debugger->onMessage(3, "Cannot relocate script '%s' while is running.", script->name);
	} else {
		int size = getScriptSize(script);
		if (relocateCode(script->instructionAddress, size, dstIp)) {
			script->instructionAddress = dstIp;
			return true;
		}
	}
	return false;
}

int parseCode(const char* code, const char* filename) {
	collectGarbage();
	ScriptEntry* lastEntry = NULL;
	ScriptEntry* entry = *ScriptLibraryR.pScriptList;
	while (entry != NULL) {
		lastEntry = entry;
		entry = entry->next;
	}
	//
	TRACE("parsing code\n%s", code);
	char tmpdir[MAX_PATH];
	char tmpfile[MAX_PATH];
	if (tmpnam(tmpfile) == NULL) {
		ERR("unable to get temporary file");
		return 2;
	}
	if (filename != NULL) {
		strcpy(tmpdir, tmpfile);
		if (_mkdir(tmpdir) != 0) {
			ERR("unable to create temporary directory");
			return 2;
		}
		strcat(tmpfile, "\\");
		strcat(tmpfile, filename);
	}
	TRACE("writing temporary script to %s", tmpfile);
	FILE* tmpFile = fopen(tmpfile, "w");
	if (!tmpFile) {
		ERR("unable to open file %s for write", tmpfile);
		return 2;
	}
	fwrite(code, 1, strlen(code), tmpFile);
	fclose(tmpFile);
	#if LOG_LEVEL >= LL_DEEP_TRACE
		*ScriptLibraryR.pParserTraceEnabled = 1;
	#endif
	*ScriptLibraryR.pErrorsCount = 0;
	const int prevInstructionsCount = getTotalInstructions();
	DEBUG("compiling code");
	int r = ScriptLibraryR.ParseFile(NULL, tmpfile, gamePath);
	if (r == 0) {
		DEBUG("code compiled without errors");
		//Insert the new scripts in a LIFO so we can read back them in reverse order
		std::stack<Script*> scriptsToMove;
		entry = lastEntry != NULL ? lastEntry->next : *ScriptLibraryR.pScriptList;
		while (entry != NULL) {
			scriptsToMove.push(entry->script);
			entry = entry->next;
		}
		//Relocate the scripts from the last
		DEBUG("relocating scripts");
		while (!scriptsToMove.empty()) {
			Script* script = scriptsToMove.top();
			scriptsToMove.pop();
			const size_t scriptSize = getScriptSize(script);
			const int newAddress = memoryManager.getFreeSpace(scriptSize);
			if (newAddress >= 0) {
				const int prevAddress = script->instructionAddress;
				DEBUG("relocating script '%s' from %i to %i", script->name, prevAddress, newAddress);
				if (relocateScript(script, newAddress)) {
					DEBUG("marking instructions %i -> %i as free space", prevAddress, prevAddress + scriptSize);
					memoryManager.addFreeSpace(prevAddress, scriptSize);
				} else {
					ERR("code relocation failed");
					memoryManager.addFreeSpace(newAddress, scriptSize);
				}
			}
		}
		const int currentSize = getTotalInstructions();
		const int newSize = memoryManager.setTotalSize(currentSize);
		if (newSize < currentSize) {
			DEBUG("shrinking code array from %i to %i instructions", currentSize, newSize);
			ScriptLibraryR.instructions->pEnd = ScriptLibraryR.instructions->pFirst + newSize;
		}
	} else {
		DEBUG("compile failed with code %i", r);
		//Delete new scripts compiled before errors occurred
		entry = lastEntry != NULL ? lastEntry->next : *ScriptLibraryR.pScriptList;
		while (entry != NULL) {
			ScriptEntry* nextEntry = entry->next;
			Script* script = entry->script;
			DEBUG("deleting script '%s'", script->name);
			deleteScript0(script, false);	//No need to mark code as free space, the array will be shrinked all at once
			ScriptLibraryR.free0(entry);
			entry = nextEntry;
		}
		if (lastEntry == NULL) {
			*ScriptLibraryR.pScriptList = NULL;
		} else {
			lastEntry->next = NULL;
		}
		if (getTotalInstructions() > prevInstructionsCount) {
			DEBUG("shrinking code array from %i to %i instructions", getTotalInstructions(), prevInstructionsCount);
			ScriptLibraryR.instructions->pEnd = ScriptLibraryR.instructions->pFirst + prevInstructionsCount;
		}
	}
	_unlink(tmpfile);
	if (filename != NULL) {
		int r2 = _rmdir(tmpdir);
	}
	return r;
}

Expression* compileExpression0(Script* script, const std::string sExpression, int datatype) {
	TRACE("compiling expression '%s'", sExpression.c_str());
	int varId = getVarId(script, sExpression.c_str());
	if (varId >= 0) {
		Expression* expr = new Expression(sExpression, DT_FLOAT, script, varId);
		unusedExpressionsSize += expr->getSize();
		return expr;
	}
	if (varId == INDEX_OUT_OF_BOUNDS) {
		return NULL;
	}
	char filename[32];
	sprintf(filename, "__debugger_%i", *ScriptLibraryR.pHighestScriptId + 1);
	char scriptName[44];
	sprintf(scriptName, "__debugger_eval_%i", *ScriptLibraryR.pHighestScriptId + 1);
	//Copy local variable declarations from context script
	char localDecl[1024];
	localDecl[0] = 0;
	int initLocalCount = 0;
	if (script != NULL && script->localVars.pEnd - script->localVars.pFirst > 0) {
		TRACE("copying local variables");
		char* writePos = localDecl;
		const char* lastName = **script->localVars.pFirst;
		int size = 1;
		for (char*** ppVarName = script->localVars.pFirst + 1; ppVarName <= script->localVars.pEnd; ppVarName++) {
			const char* varName = ppVarName < script->localVars.pEnd ? **ppVarName : "";
			if (streq(varName, "LHVMA")) {
				size++;
			} else {
				if (size == 1) {
					writePos += sprintf(writePos, "	%s=0\n", lastName);
					initLocalCount++;	//Do this only for atomic vars, not arrays!
				} else {
					writePos += sprintf(writePos, "	%s[%i]\n", lastName, size);
				}
				lastName = varName;
				size = 1;
			}
		}
	}
	//Split code from return value (last line)
	TRACE("splitting code from return value");
	std::string init = "";
	std::string rExpression = sExpression;
	size_t lastEol = sExpression.find_last_of("\n");
	if (lastEol != std::string::npos) {
		init = sExpression.substr(0, lastEol + 1);
		rExpression = sExpression.substr(lastEol + 1);
	}
	//Build the code
	TRACE("building the code");
	const char* codeTemplate;
	switch (datatype) {
		case DT_FLOAT:
			initLocalCount += 1;
			codeTemplate =
				"begin script %1$s\n"
				"%2$s"
				"	__debugger_result = 0\n"
				"start\n"
				"%3$s"
				"	__debugger_result = %4$s\n"
				"end script %1$s";
			break;
		case DT_INT:
			initLocalCount += 1;
			codeTemplate =
				"begin script %1$s\n"
				"%2$s"
				"	__debugger_result = 0\n"
				"start\n"
				"%3$s"
				"	__debugger_result = variable %4$s\n"
				"end script %1$s";
			break;
		case DT_BOOLEAN:
			initLocalCount += 1;
			codeTemplate =
				"begin script %1$s\n"
				"%2$s"
				"	__debugger_result = 0\n"
				"start\n"
				"%3$s"
				"	__debugger_result = 0\n"
				"	if %4$s\n"
				"		__debugger_result = 1\n"
				"	end if\n"
				"end script %1$s";
			break;
		case DT_COORDS:
			initLocalCount += 4;
			codeTemplate =
				"begin script %1$s\n"
				"%2$s"
				"	__debugger_result = 0\n"
				"	__debugger_result_x = 0\n"
				"	__debugger_result_y = 0\n"
				"	__debugger_result_z = 0\n"
				"start\n"
				"%3$s"
				"	__debugger_result = marker at (%4$s)\n"
				"	__debugger_result_x = SCRIPT_OBJECT_PROPERTY_TYPE_XPOS of __debugger_result\n"
				"	__debugger_result_y = SCRIPT_OBJECT_PROPERTY_TYPE_YPOS of __debugger_result\n"
				"	__debugger_result_z = SCRIPT_OBJECT_PROPERTY_TYPE_ZPOS of __debugger_result\n"
				"	delete __debugger_result\n"
				"end script %1$s";
			break;
		default:
			debugger->onMessage(3, "unsupported datatype");
			return NULL;
	}
	const int bytes = strlen(codeTemplate) + 2 * strlen(scriptName) + strlen(localDecl) + init.length() + rExpression.length() + 1;
	char* code = (char*)malloc(bytes);
	if (code == NULL) {
		ERR("failed to allocate %i bytes", bytes);
		return NULL;
	}
	int r = _sprintf_p(code, bytes, codeTemplate, scriptName, localDecl, init.c_str(), rExpression.c_str());
	if (r == -1) {
		ERR("error preparing the code");
		return NULL;
	}
	//Compile
	TRACE("compiling the code");
	r = parseCode(code, filename);
	free(code);
	if (r) {
		DEBUG("error %i compiling expression", r);
		return NULL;
	}
	TRACE("code compiled without errors");
	//Find the script just added (always the last)
	ScriptEntry* prevEntry = NULL;
	ScriptEntry* scriptEntry = *ScriptLibraryR.pScriptList;
	while (scriptEntry->next != NULL) {
		prevEntry = scriptEntry;
		scriptEntry = scriptEntry->next;
	}
	Script* newScript = scriptEntry->script;
	if (!streq(newScript->name, scriptName)) {	//Check that the script name matches with the expected name
		debugger->onMessage(3, "failed to retrieve new script");
		return NULL;
	}
	TRACE("expression compiled as script %i with access to %i global vars", newScript->id, newScript->globalsCount);
	/*#if LOG_LEVEL >= LL_TRACE
	for (int i = pScript->instructionAddress; ; i++) {
		Instruction* instr = &ScriptLibraryR.instructions->pFirst[i];
		formatInstruction(pScript, instr, buffer);
		printf("%i: %s\n", i, buffer);
		if (instr->opcode == END) break;
	}
	#endif*/
	//Retrieve the script properties
	const int globalsCount = newScript->globalsCount;
	const DWORD start = newScript->instructionAddress;
	const DWORD instructionAddress = newScript->instructionAddress + 2 + initLocalCount * 2;		//Skip instructions before "start"
	const int ipEnd = findInstruction(newScript->instructionAddress, END);
	const int size = ipEnd - start + 1;
	ScriptLibraryR.instructions->pFirst[ipEnd - 3] = ScriptLibraryR.instructions->pFirst[ipEnd];	//Return before exception handler
	DEBUG("expression compiled at IP %i, %i instructions", start, size);
	//Remove the script entry and the script itself...
	if (prevEntry == NULL) {
		*ScriptLibraryR.pScriptList = NULL;
	} else {
		prevEntry->next = NULL;
	}
	ScriptLibraryR.free0(scriptEntry);
	(*ScriptLibraryR.pScriptsCount)--;
	(*ScriptLibraryR.pHighestScriptId)--;
	deleteScript0(newScript, false);	//... without deleting the code
	//
	#if LOG_LEVEL >= LL_TRACE
	char buffer[80];
	TRACE("compiled code:");
	for (int i = instructionAddress; ; i++) {
		Instruction* instr = &ScriptLibraryR.instructions->pFirst[i];
		formatInstruction(newScript, instr, buffer);
		printf("%i: %s\n", i, buffer);
		if (instr->opcode == END) break;
	}
	#endif
	//
	Expression* expr = new Expression(sExpression, datatype, script, globalsCount, start, size, instructionAddress);
	unusedExpressionsSize += expr->getSize();
	return expr;
}

bool checkMessage(ParserMessages messages, DWORD minSeverity, std::string text) {
	for (auto msg : messages) {
		if (msg.first >= minSeverity && msg.second.find(text) != std::string::npos) {
			return true;
		}
	}
	return false;
}

void throwParserMessages(ParserMessages messages) {
	if (parseMessagesTraps.empty() || *parseMessagesTraps.top() != messages) {
		for (auto msg : messages) {
			errorCallback(msg.first, msg.second.c_str());
		}
	} else {
		ERR("cannot throw messages in the same trap");
	}
}

Expression* tryCompileExpression(Script* script, std::string expression, int datatype, ParserMessages* outTrap) {
	parseMessagesTraps.push(outTrap);
	Expression* expr = compileExpression0(script, expression, datatype);
	parseMessagesTraps.pop();
	return expr;
}

Expression* compileExpression(Script* script, std::string expression, int datatype) {
	if (datatype == DT_AUTODETECT) {
		DEBUG("trying to compile expression as float...");
		ParserMessages messages0;
		Expression* expr = tryCompileExpression(script, expression, DT_FLOAT, &messages0);
		if (expr != NULL) return expr;
		if (!checkMessage(messages0, 0, "parse error")) {
			throwParserMessages(messages0);
			return NULL;
		}
		DEBUG("expression is not of type float, trying as bool...");
		//
		ParserMessages messages;
		expr = tryCompileExpression(script, expression, DT_BOOLEAN, &messages);
		if (expr != NULL) return expr;
		if (!checkMessage(messages, 0, "parse error")) {
			throwParserMessages(messages);
			return NULL;
		}
		DEBUG("expression is not of type float, trying as coords...");
		//
		expr = tryCompileExpression(script, expression, DT_COORDS, &messages);
		if (expr != NULL) return expr;
		if (!checkMessage(messages, 0, "parse error")) {
			throwParserMessages(messages);
			return NULL;
		}
		DEBUG("expression is not of type coords, trying as int...");
		//
		expr = tryCompileExpression(script, expression, DT_INT, &messages);
		if (expr != NULL) return expr;
		DEBUG("failed to compile expression");
		//
		throwParserMessages(messages0);
		return NULL;
	} else {
		return compileExpression0(script, expression, datatype);
	}
}

size_t deleteExpression(Expression* expr) {
	if (expr->refCount > 0) {
		ERR("cannot delete expression '%s' because it has %i references", expr->str.c_str(), expr->refCount);
		return 0;
	}
	const size_t size = expr->getSize();
	//Remove expression from cache
	const int scriptId = expr->script != NULL ? expr->script->id : 0;
	if (expressionsCache.contains(scriptId)) {
		auto& cache = expressionsCache[scriptId];
		if (cache.contains(expr->str)) {
			cache.erase(expr->str);
			DEBUG("expression '%s' removed from cache, %i bytes freed", expr->str.c_str(), size);
		} else {
			DEBUG("expression '%s' not found in cache", expr->str.c_str());
		}
	} else {
		DEBUG("cache for script %i not found", scriptId);
	}
	//Free code space
	if (expr->start >= 0) {
		DEBUG("marking instructions %i -> %i as free space", expr->start, expr->start + expr->instructionsCount);
		memoryManager.addFreeSpace(expr->start, expr->instructionsCount);
	}
	//
	unusedExpressionsSize -= size;
	delete expr;
	return size;
}

void deleteUnusedExpressions() {
	for (auto cacheEntry : expressionsCache) {
		auto& cache = cacheEntry.second;
		for (auto it = cache.begin(); it != cache.end(); ) {
			auto expr = (*it).second;
			if (expr->refCount == 0) {
				DEBUG("expression '%s' has 0 references, removing from cache", (*it).first.c_str());
				size_t freed = deleteExpression(expr);
				cache.erase(it++);
			} else {
				++it;
			}
		}
	}
}

void collectGarbage() {
	bool shrink = false;
	if (unusedExpressionsSize > MAX_UNUSED_EXPRESSIONS_BYTES) {
		DEBUG("collecting garbage");
		deleteUnusedExpressions();
		shrink = true;
	}
	if (shrink) {
		const int currentSize = getTotalInstructions();
		#if LOG_LEVEL >= LL_TRACE
			memoryManager.printSegments();
			printf("Total: %i\n", currentSize);
		#endif
		const int newSize = memoryManager.setTotalSize(currentSize);
		if (newSize < currentSize) {
			DEBUG("shrinking code array from %i to %i instructions", currentSize, newSize);
			ScriptLibraryR.instructions->pEnd = ScriptLibraryR.instructions->pFirst + newSize;
		}
	}
}

Expression* getCompiledExpression(Script* script, std::string expression, int datatype) {
	int scriptId = script != NULL ? script->id : 0;
	if (!expressionsCache.contains(scriptId)) {
		expressionsCache[scriptId] = std::unordered_map<std::string, Expression*>();
		TRACE("expression cache for script %i initialized", scriptId);
	}
	auto& cache = expressionsCache[scriptId];
	if (!cache.contains(expression)) {
		Expression* expr = compileExpression(script, expression, datatype);
		if (expr == NULL) return NULL;
		cache[expression] = expr;
		DEBUG("expression %s, at IP %i added to cache", expression.c_str(), expr->start);
	} else {
		TRACE("expression %s retrieved from cache", expression.c_str());
	}
	return cache[expression];
}

Var* evalExpression(Task* context, Expression* expr) {
	TRACE("evaluating expression '%s' at address %i", expr->str.c_str(), expr->instructionAddress);
	if (expr->varId >= 0) {
		return getVarById(context, expr->varId);
	}
	const int addedVarsCount = expr->datatype == DT_COORDS ? 4 : 1;
	Task evalTask;
	Var tmpLocals[4];
	evalTask.globalsCount = expr->globalsCount;
	int localVarsCount = 0;
	if (context != NULL) {
		Script* script = getTaskScript(context);
		const int scriptLocalVarsCount = script->localVars.pEnd - script->localVars.pFirst;
		const int taskLocalVarsCount = getLocalVarsCount(context);
		const int requiredVarsCount = scriptLocalVarsCount + addedVarsCount;
		if (taskLocalVarsCount < requiredVarsCount) {
			const int bytes = sizeof(Var) * requiredVarsCount;
			Var* newLocalVars = (Var*)ScriptLibraryR.operator_new(bytes);
			if (newLocalVars == NULL) {
				ERR("failed to allocate %i bytes", bytes);
				return NULL;
			}
			if (taskLocalVarsCount > 0) {
				for (int i = 0; i < taskLocalVarsCount; i++) {
					newLocalVars[i] = context->localVars.pFirst[i];
				}
				ScriptLibraryR.free0(context->localVars.pFirst);
			}
			context->localVars.pFirst = newLocalVars;
			context->localVars.pEnd = newLocalVars + requiredVarsCount;
			context->localVars.pBufferEnd = newLocalVars + requiredVarsCount;
		}
		evalTask.localVars.pFirst = context->localVars.pFirst;
		evalTask.localVars.pEnd = context->localVars.pEnd;
		evalTask.localVars.pBufferEnd = context->localVars.pBufferEnd;
	} else {
		evalTask.localVars.pFirst = tmpLocals;
		evalTask.localVars.pEnd = tmpLocals + addedVarsCount;
		evalTask.localVars.pBufferEnd = tmpLocals + addedVarsCount;
	}
	//
	Var* result;
	if (expr->datatype == DT_COORDS) {
		result = evalTask.localVars.pEnd - 3;
		result[-1].name = "__debugger_result";
		result[-1].type = 2;
		result[-1].floatVal = NAN;
		result[0].name = "__debugger_result_x";
		result[0].type = 2;
		result[0].floatVal = NAN;
		result[1].name = "__debugger_result_y";
		result[1].type = 2;
		result[1].floatVal = NAN;
		result[2].name = "__debugger_result_z";
		result[2].type = 2;
		result[2].floatVal = NAN;
	} else {
		result = evalTask.localVars.pEnd - 1;
		result->name = "__debugger_result";
		result->type = 2;
		result->floatVal = NAN;
	}
	//
	evalTask.currentExceptionHandlerIndex = 0;
	evalTask.exceptionHandlerIps.pFirst = 0;
	evalTask.exceptionHandlerIps.pEnd = 0;
	evalTask.filename = (char*)"__debugger";
	evalTask.inExceptionHandler = 0;
	evalTask.instructionAddress = expr->instructionAddress;
	evalTask.ip = expr->instructionAddress;
	evalTask.name = (char*)"__debugger";
	evalTask.prevIp = expr->instructionAddress;
	evalTask.scriptID = -1;
	evalTask.sleeping = 0;
	evalTask.stack.count = 0;
	evalTask.stack.totalPop = 0;
	evalTask.stack.totalPush = 0;
	evalTask.stop = 0;
	evalTask.stopExceptionHandler = 1;
	evalTask.taskNumber = -1;
	evalTask.ticks = 0;
	evalTask.type = -1;
	evalTask.waitingTask = 0;
	//
	Task*& currentTask = *ScriptLibraryR.ppCurrentTask;
	Task* prevTask = currentTask;
	currentTask = &evalTask;
	while (!evalTask.stop) {
		Instruction& instruction = ScriptLibraryR.instructions->pFirst[evalTask.ip];
		#if LOG_LEVEL >= LL_TRACE
			char buffer[80];
			formatTaskInstruction(&evalTask, &instruction, buffer);
			TRACE("eval: %i: %s", evalTask.ip, buffer);
		#endif
		OpcodeImpl opcodeImpl = ScriptLibraryR.opcodesImpl[instruction.opcode];
		opcodeImpl(currentTask, &instruction);
		++evalTask.ip;
	}
	currentTask = prevTask;
	//
	return result;
}

Var* evalString(Task* context, std::string expression, int& datatype) {
	if (isNumber(expression)) {
		datatype = DT_FLOAT;
		resultVar.floatVal = (FLOAT)atof(expression.c_str());
		return &resultVar;
	}
	Script* script = getTaskScript(context);
	if (datatype != DT_COORDS) {
		int varId = getVarId(script, expression.c_str());
		if (varId >= 0) {
			datatype = DT_FLOAT;
			return getVarById(context, varId);
		}
	}
	Expression* expr = getCompiledExpression(script, expression, datatype);
	if (expr == NULL) return NULL;
	datatype = expr->datatype;
	return evalExpression(context, expr);
}

Breakpoint* setBreakpoint(std::string filename, DWORD lineno, DWORD ip, Task* thread, const char* sCondition) {
	if (breakpoints.contains(ip)) {
		debugger->onMessage(3, "a breakpoint exists at instruction %i", ip);
		return NULL;
	}
	Script* script = findScriptByIp(ip);
	if (script == NULL) {
		debugger->onMessage(3, "cannot find script for instruction at %i", ip);
		return NULL;
	}
	Breakpoint* breakpoint = new Breakpoint(filename, lineno, script, ip, thread);
	if (sCondition != NULL) {
		Expression* cond = getCompiledExpression(script, sCondition, DT_BOOLEAN);
		if (cond == NULL) {
			delete breakpoint;
			return NULL;
		}
		breakpoint->setCondition(cond);
		unusedExpressionsSize -= cond->getSize();
	}
	breakpoints[ip] = breakpoint;
	TRACE("breakpoint set at %i", ip);
	return breakpoint;
}

bool unsetBreakpoint(Breakpoint* breakpoint) {
	if (breakpoints.contains(breakpoint->ip)) {
		breakpoints.erase(breakpoint->ip);
		if (breakpoint->getCondition() != NULL) {
			unusedExpressionsSize += breakpoint->getCondition()->getSize();
		}
		delete breakpoint;
		return true;
	} else {
		return false;
	}
}

Breakpoint* getBreakpointByIndex(DWORD index) {
	if (index >= 0 && index < (int)breakpoints.size()) {
		auto it = breakpoints.begin();
		std::advance(it, index);
		return (*it).second;
	} else {
		return NULL;
	}
}

Breakpoint* getBreakpointAtLine(std::string filename, DWORD lineno) {
	for (auto entry : breakpoints) {
		Breakpoint* breakpoint = entry.second;
		if (breakpoint->lineno == lineno && breakpoint->filename == filename) {
			return breakpoint;
		}
	}
	return NULL;
}

Breakpoint* getBreakpointAtAddress(int ip) {
	if (ip >= 0 && ip < getTotalInstructions()) {
		return breakpoints[ip];
	} else {
		return NULL;
	}
}

std::list<Breakpoint*> getBreakpoints() {
	auto res = std::list<Breakpoint*>();
	for (auto entry : breakpoints) {
		Breakpoint* breakpoint = entry.second;
		res.push_back(breakpoint);
	}
	return res;
}

bool setCondition(Breakpoint* breakpoint, const char* condition) {
	if (condition != NULL) {
		Expression* expr = getCompiledExpression(breakpoint->script, condition, DT_BOOLEAN);
		if (expr == NULL) return false;
		if (breakpoint->getCondition() != NULL) {
			unusedExpressionsSize += breakpoint->getCondition()->getSize();
		}
		breakpoint->setCondition(expr);
		unusedExpressionsSize -= expr->getSize();
	} else {
		if (breakpoint->getCondition() != NULL) {
			unusedExpressionsSize += breakpoint->getCondition()->getSize();
		}
		breakpoint->setCondition(NULL);
	}
	return true;
}

Watch* addWatch(Task* task, const char* expression) {
	//Try in global context first
	TRACE("trying to compile expression in global context");
	ParserMessages messages;
	parseMessagesTraps.push(&messages);
	Expression* expr = compileExpression(NULL, expression, DT_AUTODETECT);
	parseMessagesTraps.pop();
	if (expr == NULL) {
		if (!checkMessage(messages, 0, "Unable to find variable")) {
			TRACE("syntax error");
			throwParserMessages(messages);
			return NULL;
		}
		//Retry in task context
		if (task == NULL) {
			debugger->onMessage(3, "Failed to compile expression");
			return NULL;
		}
		Script* script = getTaskScript(task);
		TRACE("trying to compile expression in %s context", script->name);
		expr = getCompiledExpression(script, expression, DT_AUTODETECT);
		if (expr == NULL) {
			return NULL;
		}
		DEBUG("expression %s compiled in \"%s\" context", expression, script->name);
	} else {
		task = NULL;
		DEBUG("expression %s compiled in global context", expression);
	}
	Watch* watch = new Watch(task, expr);
	unusedExpressionsSize -= expr->getSize();
	const std::string key = watch->getKey();
	if (watches.contains(key)) {
		debugger->onMessage(2, "Watch already exists.");
		delete watch;
		watch = watches[key];
	} else {
		Var* val = evalExpression(task, expr);
		if (val != NULL) {
			DEBUG("initial value: %f", val->floatVal);
			watch->oldValue = val->floatVal;
		}
		watches[key] = watch;
	}
	return watch;
}

std::list<Watch*> getWatches() {
	std::list<Watch*> res;
	for (auto entry : watches) {
		res.push_back(entry.second);
	}
	return res;
}

Watch* getWatchByIndex(DWORD index) {
	if (index >= 0 && index < (int)watches.size()) {
		auto it = watches.begin();
		std::advance(it, index);
		return (*it).second;
	} else {
		return NULL;
	}
}

bool deleteWatch(Watch* watch) {
	if (watches.contains(watch->getKey())) {
		watches.erase(watch->getKey());
		unusedExpressionsSize += watch->getExpression()->getSize();
		delete watch;
		return true;
	} else {
		return false;
	}
}

DWORD __cdecl ScriptLibraryR_doStartScript(Script* pScript) {
	//TRACE("ScriptLibraryR_doStartScript(%p)", pScript);
	DWORD newTaskId = ScriptLibraryR.doStartScript(pScript);
	tasksInfo[newTaskId] = new TaskInfo();
	if (caller != NULL) {
		tasksParents[newTaskId] = caller;
		caller = NULL;
	} else {
		Task* thread = getTaskById(newTaskId);
		threads[newTaskId] = thread;
		debugger->threadStarted(thread);
	}
	return newTaskId;
}

int __cdecl ScriptLibraryR_stopTask0(Task* pTask) {
	//TRACE("ScriptLibraryR_stopTask0(%p)", pTask);
	for (auto it = watches.begin(); it != watches.end(); it++) {
		Watch* watch = (*it).second;
		if (watch->task == pTask) {
			it = watches.erase(it);
			delete watch;
			it--;
		}
	}
	//
	if (tasksParents.contains(pTask->taskNumber)) {
		tasksParents.erase(pTask->taskNumber);
	} else {
		threads.erase(pTask->taskNumber);
		debugger->threadEnded(pTask);
		if (pTask->taskNumber == allowedThreadId) {
			allowedThreadId = 0;
		}
	}
	auto taskInfo = tasksInfo[pTask->taskNumber];
	tasksInfo.erase(pTask->taskNumber);
	delete taskInfo;
	return ScriptLibraryR.stopTask0(pTask);	//This frees the memory, so must be called after
}

DWORD __cdecl ScriptLibraryR_opcode_24_CALL(Task* pTask, Instruction* pInstr) {
	if (pInstr->flags != 2) {
		caller = pTask;	//flags != 2 means wait for the child task to terminate (sync call)
	}
	DWORD taskId = ScriptLibraryR.opcode_24_CALL(pTask, pInstr);
	return taskId;
}

int __cdecl errorCallback(DWORD severity, const char* msg) {
	if (parseMessagesTraps.empty()) {
		std::string msg2 = strReplace(msg, parseTempFile, "eval");
		debugger->onMessage(severity, "%s", msg2.c_str());
		if (originalErrCallback != NULL) {
			return originalErrCallback(severity, msg);
		}
	} else {
		parseMessagesTraps.top()->push_back(std::pair<DWORD, std::string>(severity, msg));
	}
	return 0;
}

int __cdecl ScriptLibraryR_Initialise(int a1, LPVOID pNativeFuncs, ErrorCallback errCallback, int a4, int a5, int a6, int a7) {
	DEBUG("ScriptLibraryR.Initialise(%i, %p, %p, %i, %i, %i, %i)", a1, pNativeFuncs, errCallback, a4, a5, a6, a7);
	int r = ScriptLibraryR.Initialise(a1, pNativeFuncs, errCallback, a4, a5, a6, a7);
	originalErrCallback = errCallback;
	*ScriptLibraryR.pErrorCallback = errorCallback;
	return r;
}

void detourScriptLibraryR() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	//Exported functions
	DETOUR(ScriptLibraryR.Initialise, ScriptLibraryR_Initialise);
	DETOUR(ScriptLibraryR.LoadBinary, ScriptLibraryR_LoadBinary);
	DETOUR(ScriptLibraryR.RestoreState, ScriptLibraryR_RestoreState);
	DETOUR(ScriptLibraryR.StartScript, ScriptLibraryR_StartScript);
	//Internal functions
	DETOUR(ScriptLibraryR.doStartScript, ScriptLibraryR_doStartScript);
	DETOUR(ScriptLibraryR.stopTask0, ScriptLibraryR_stopTask0);
	DETOUR(ScriptLibraryR.lhvmCpuLoop, ScriptLibraryR_lhvmCpuLoop);
	DETOUR(ScriptLibraryR.opcode_24_CALL, ScriptLibraryR_opcode_24_CALL);
	//
	if (DetourTransactionCommit() == NO_ERROR) {
		INFO("ScriptLibraryR hooked successfully");
	} else {
		ERR("failed to hook ScriptLibraryR");
	}
}

void initScriptLibraryR() {
	ScriptLibraryR.hmod = GetModuleHandleA("ScriptLibraryR.DLL");
	if (ScriptLibraryR.hmod == NULL) {
		ERR("failed to get handle to ScriptLibraryR");
	} else {
		//Exported functions
		ScriptLibraryR.pAutoStart = GetProcAddress(ScriptLibraryR.hmod, "AutoStart");
		ScriptLibraryR.pCodeSize = GetProcAddress(ScriptLibraryR.hmod, "CodeSize");
		ScriptLibraryR.pFindScript = GetProcAddress(ScriptLibraryR.hmod, "FindScript");
		ScriptLibraryR.pGetCurrentScriptType = GetProcAddress(ScriptLibraryR.hmod, "GetCurrentScriptType");
		ScriptLibraryR.pGetFirstRunningTaskId = GetProcAddress(ScriptLibraryR.hmod, "GetFirstRunningTaskId");
		ScriptLibraryR.pGetGlobalVariableValue = GetProcAddress(ScriptLibraryR.hmod, "GetGlobalVariableValue");
		ScriptLibraryR.pGetHighestRunningTask = GetProcAddress(ScriptLibraryR.hmod, "GetHighestRunningTask");
		ScriptLibraryR.pGetLocalVariableValue = GetProcAddress(ScriptLibraryR.hmod, "GetLocalVariableValue");
		ScriptLibraryR.pGetNextTask = GetProcAddress(ScriptLibraryR.hmod, "GetNextTask");
		ScriptLibraryR.pGetPreviousTask = GetProcAddress(ScriptLibraryR.hmod, "GetPreviousTask");
		ScriptLibraryR.pGetScriptID = GetProcAddress(ScriptLibraryR.hmod, "GetScriptID");
		ScriptLibraryR.pGetScriptInstructionCount = GetProcAddress(ScriptLibraryR.hmod, "GetScriptInstructionCount");
		ScriptLibraryR.pGetScriptType = GetProcAddress(ScriptLibraryR.hmod, "GetScriptType");
		ScriptLibraryR.pGetTaskFilename = GetProcAddress(ScriptLibraryR.hmod, "GetTaskFilename");
		ScriptLibraryR.pGetTaskName = GetProcAddress(ScriptLibraryR.hmod, "GetTaskName");
		ScriptLibraryR.pInitialise = GetProcAddress(ScriptLibraryR.hmod, "Initialise");
		ScriptLibraryR.pLineNumber = GetProcAddress(ScriptLibraryR.hmod, "LineNumber");
		ScriptLibraryR.pLoadBinary = GetProcAddress(ScriptLibraryR.hmod, "LoadBinary");
		ScriptLibraryR.pLookIn = GetProcAddress(ScriptLibraryR.hmod, "LookIn");
		ScriptLibraryR.pLoopGlobalVariables = GetProcAddress(ScriptLibraryR.hmod, "LoopGlobalVariables");
		ScriptLibraryR.pLoopTaskVariables = GetProcAddress(ScriptLibraryR.hmod, "LoopTaskVariables");
		ScriptLibraryR.pMode = GetProcAddress(ScriptLibraryR.hmod, "Mode");
		ScriptLibraryR.pNumTasks = GetProcAddress(ScriptLibraryR.hmod, "NumTasks");
		ScriptLibraryR.pOpCode = GetProcAddress(ScriptLibraryR.hmod, "OpCode");
		ScriptLibraryR.pOpCodeName = GetProcAddress(ScriptLibraryR.hmod, "OpCodeName");
		ScriptLibraryR.pPOP = GetProcAddress(ScriptLibraryR.hmod, "POP");
		ScriptLibraryR.pPUSH = GetProcAddress(ScriptLibraryR.hmod, "PUSH");
		ScriptLibraryR.pParseFile = GetProcAddress(ScriptLibraryR.hmod, "ParseFile");
		ScriptLibraryR.pParsedFile = GetProcAddress(ScriptLibraryR.hmod, "ParsedFile");
		ScriptLibraryR.pReboot = GetProcAddress(ScriptLibraryR.hmod, "Reboot");
		ScriptLibraryR.pRestoreState = GetProcAddress(ScriptLibraryR.hmod, "RestoreState");
		ScriptLibraryR.pSTRING = GetProcAddress(ScriptLibraryR.hmod, "STRING");
		ScriptLibraryR.pSaveBinary = GetProcAddress(ScriptLibraryR.hmod, "SaveBinary");
		ScriptLibraryR.pSaveState = GetProcAddress(ScriptLibraryR.hmod, "SaveState");
		ScriptLibraryR.pStartScript = GetProcAddress(ScriptLibraryR.hmod, "StartScript");
		ScriptLibraryR.pStopAllTasks = GetProcAddress(ScriptLibraryR.hmod, "StopAllTasks");
		ScriptLibraryR.pStopScripts = GetProcAddress(ScriptLibraryR.hmod, "StopScripts");
		ScriptLibraryR.pStopTask = GetProcAddress(ScriptLibraryR.hmod, "StopTask");
		ScriptLibraryR.pStopTasksOfType = GetProcAddress(ScriptLibraryR.hmod, "StopTasksOfType");
		ScriptLibraryR.pTaskFilename = GetProcAddress(ScriptLibraryR.hmod, "TaskFilename");
		ScriptLibraryR.pTaskName = GetProcAddress(ScriptLibraryR.hmod, "TaskName");
		ScriptLibraryR.pTaskNumber = GetProcAddress(ScriptLibraryR.hmod, "TaskNumber");
		ScriptLibraryR.pType = GetProcAddress(ScriptLibraryR.hmod, "Type");
		ScriptLibraryR.pUnInitialize = GetProcAddress(ScriptLibraryR.hmod, "UnInitialize");
		ScriptLibraryR.pValue = GetProcAddress(ScriptLibraryR.hmod, "Value");
		ScriptLibraryR.pVersion = GetProcAddress(ScriptLibraryR.hmod, "Version");
		//
		int version = ScriptLibraryR.Version();
		if (version == 8) {
			//Internal functions
			ScriptLibraryR.pLoadGameHeaders			= (FARPROC)(ScriptLibraryR.base + loadGameHeadersOffset);
			ScriptLibraryR.pGetVarType				= (FARPROC)(ScriptLibraryR.base + getVarTypeOffset);
			ScriptLibraryR.pSetVarType				= (FARPROC)(ScriptLibraryR.base + setVarTypeOffset);
			ScriptLibraryR.pCreateVar				= (FARPROC)(ScriptLibraryR.base + createVarOffset);
			ScriptLibraryR.pDoStartScript			= (FARPROC)(ScriptLibraryR.base + doStartScriptOffset);
			ScriptLibraryR.pStopTask0				= (FARPROC)(ScriptLibraryR.base + stopTask0Offset);
			ScriptLibraryR.pTaskExists				= (FARPROC)(ScriptLibraryR.base + taskExistsOffset);
			ScriptLibraryR.pReadTask				= (FARPROC)(ScriptLibraryR.base + readTaskOffset);
			ScriptLibraryR.pLhvmCpuLoop				= (FARPROC)(ScriptLibraryR.base + lhvmCpuLoopOffset);
			ScriptLibraryR.pOpcode_24_CALL			= (FARPROC)(ScriptLibraryR.base + opcode_24_CALL_Offset);
			ScriptLibraryR.pGetExceptionHandlersCount= (FARPROC)(ScriptLibraryR.base + getExceptionHandlersCountOffset);
			ScriptLibraryR.pGetExceptionHandlerCurrentIp = (FARPROC)(ScriptLibraryR.base + getExceptionHandlerCurrentIpOffset);
			ScriptLibraryR.pParseFileImpl			= (FARPROC)(ScriptLibraryR.base + parseFileImplOffset);
			//Statically linked C-runtime functions
			ScriptLibraryR.pOperator_new			= (FARPROC)(ScriptLibraryR.base + operator_new_Offset);
			ScriptLibraryR.pFree					= (FARPROC)(ScriptLibraryR.base + freeOffset);
			ScriptLibraryR.p_strdup					= (FARPROC)(ScriptLibraryR.base + _strdupOffset);
			//Internal fields
			ScriptLibraryR.pHeadersNotLoaded		= (BYTE*)			(ScriptLibraryR.base + headersNotLoadedOffset);
			ScriptLibraryR.ppCurrentStack			= (Stack**)			(ScriptLibraryR.base + ppCurrentStackOffset);
			ScriptLibraryR.opcodesImpl				= (OpcodeImpl*)		(ScriptLibraryR.base + opcodesImplOffset);
			ScriptLibraryR.pStrNotCompiled			= (char**)			(ScriptLibraryR.base + strNotCompiledOffset);
			ScriptLibraryR.pParseFileDefaultInput	= (FILE*)			(ScriptLibraryR.base + parseFileDefaultInputOffset);
			ScriptLibraryR.instructions				= (InstructionVector*)(ScriptLibraryR.base + pInstructionsOffset);
			ScriptLibraryR.ppCurrentTaskExceptStruct= (ExceptStruct**)	(ScriptLibraryR.base + pCurrentTaskExceptStructOffset);
			ScriptLibraryR.pMainStack				= (Stack*)			(ScriptLibraryR.base + mainStackOffset);
			ScriptLibraryR.pTaskList				= (TaskEntry**)		(ScriptLibraryR.base + pTaskListOffset);
			ScriptLibraryR.pGlobalVarsDecl			= (VarTypeEntry**)	(ScriptLibraryR.base + globalVarsDeclOffset);
			ScriptLibraryR.globalVars				= (VarVector*)		(ScriptLibraryR.base + pGlobalVarsOffset);
			ScriptLibraryR.pScriptList				= (ScriptEntry**)	(ScriptLibraryR.base + pScriptListOffset);
			ScriptLibraryR.pScriptsCount			= (int*)			(ScriptLibraryR.base + pScriptsCountOffset);
			ScriptLibraryR.ppDataSection			= (char**)			(ScriptLibraryR.base + pDataSectionOffset);
			ScriptLibraryR.pDataSectionSize			= (DWORD*)			(ScriptLibraryR.base + dataSectionSizeOffset);
			ScriptLibraryR.pTicksCount				= (DWORD*)			(ScriptLibraryR.base + ticksCountOffset);
			ScriptLibraryR.pHighestScriptId			= (DWORD*)			(ScriptLibraryR.base + highestScriptIdOffset);
			ScriptLibraryR.pScriptInstructionCount	= (DWORD*)			(ScriptLibraryR.base + pScriptInstructionCountOffset);
			ScriptLibraryR.ppCurrentTask			= (Task**)			(ScriptLibraryR.base + ppCurrentTaskOffset);
			ScriptLibraryR.pErrorCallback			= (ErrorCallback*)	(ScriptLibraryR.base + errorCallbackOffset);
			ScriptLibraryR.pTaskVars				= (TaskVar*)		(ScriptLibraryR.base + taskVarsOffset);
			ScriptLibraryR.pTaskVarsCount			= (DWORD*)			(ScriptLibraryR.base + taskVarsCountOffset);
			ScriptLibraryR.pParserTraceEnabled		= (DWORD*)			(ScriptLibraryR.base + parserTraceEnabledOffset);
			ScriptLibraryR.pCurrentFilename			= (char**)			(ScriptLibraryR.base + currentFilenameOffset);
			ScriptLibraryR.ppParseFileInputStream	= (FILE**)			(ScriptLibraryR.base + pParseFileInputStreamOffset);
			ScriptLibraryR.pErrorsCount				= (DWORD**)			(ScriptLibraryR.base + errorsCountOffset);
			//
			detourScriptLibraryR();
		} else {
			Fail("ERROR: this debugger.dll can work only with LHVM 8 (Black & White: Creature Isle runtime)");
		}
	}
}

void PauseGame_Detour(int num, int edx) {
	TRACE("game paused (%d)", num);
	PauseGame(num);
}

int __fastcall GGame__LoadScriptLibrary_Detour(void* _this, int edx, int a2) {
	DEBUG("loading ScriptLibraryR...");
	int r = GGame__LoadScriptLibrary(_this, a2);
	//printf("ScriptLibraryR loaded (%i)!\n", r);
	initScriptLibraryR();
	return r;
}

void __fastcall GGame__ClearMap_Detour(void* _this, int edx) {
	GGame__ClearMap(_this);
	TRACE("map cleared");
}

void __fastcall ProcessGraphicsEngine(Game* _this, int edx) {
	IsMultiplayerGame(_this);
}

void __fastcall GGame__StartGame_Detour(Game* _this, int edx) {
	TRACE("game started");
	GGame__StartGame(_this);
}

void __fastcall GGame__Loop_Detour(void* _this, int edx) {
	TRACE("GGame::Loop - Starting...");
	if (!started) {
		started = true;
		debugger->start();
	}
	GGame__Loop(_this);
}

Game* __fastcall GScript__Reset_Detour(DWORD* _this, int edx, int a) {
	TRACE("GScript Loop - Started");
	return  GScript__Reset(_this, a);
}

char __fastcall BWCheckFeatureIsEnabled_Detour(char* _this, int edx) {
	return BWCheckFeatureIsEnabled(_this);
}

bool __fastcall GSetup__LoadMapScript_Detour(int edx) {
	TRACE("reading map...");
	return GSetup__LoadMapScript();
}

signed int __fastcall GGame__Init_Detour(void* _this, int edx) {
	TRACE("GGame_Init");
	int buffer = GGame__Init(_this);
	int buffer2 = edx;
	edx = buffer2;
	debugger->init();
	return buffer;
}

int __fastcall ControlMap__ProcessActionsPerformed_Detour(DWORD* _this, int edx) {
	//TRACE("loop");
	return ControlMap__ProcessActionsPerformed(_this);
}

void init_mods() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DETOUR(GGame__LoadScriptLibrary, GGame__LoadScriptLibrary_Detour);
	DETOUR(GGame__ClearMap, GGame__ClearMap_Detour);
	DETOUR(GGame__StartGame, GGame__StartGame_Detour);
	DETOUR(GGame__Loop, GGame__Loop_Detour);
	DETOUR(PauseGame, PauseGame_Detour);
	DETOUR(BWCheckFeatureIsEnabled, BWCheckFeatureIsEnabled_Detour);
	DETOUR(GGame__Init, GGame__Init_Detour);
	DETOUR(ControlMap__ProcessActionsPerformed, ControlMap__ProcessActionsPerformed_Detour);

	if (DetourTransactionCommit() == NO_ERROR) {
		INFO("hook successful");
	} else {
		ERR("hook error");
	}
}

void deinit_mods() {

}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	char* cmd;
	char buffer[1024];
	char* argv[32];
	int argc;
	bool useGdb, useXDebug;
	switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
			cmd = GetCommandLineA();
			useGdb = strstr(cmd, " /gdb") != NULL;
			useXDebug = strstr(cmd, " /xdebug") != NULL;
			debugging = useGdb || useXDebug || strstr(cmd, " /debug") != NULL;
			if (debugging) {
				if (useXDebug) {
					Fail("debugger: xdebug is not supported yet");
				} else {
					debugger = new Gdb();	//Default
				}
				strcpy(buffer, cmd);
				argc = splitArgs(buffer, ' ', argv, 32);
				char* sources = getArgVal(argv, argc, "/debug:src");
				if (sources != NULL) {
					char* dirs[32];
					int nDirs = splitArgs(sources, ';', dirs, 32);
					for (int i = 0; i < nDirs; i++) {
						sourcePath.insert(dirs[i]);
					}
				}
				char* incDir = getArgVal(argv, argc, "/debug:inc");
				if (incDir != NULL) {
					strcpy(gamePath, incDir);
				} else {
					GetModuleFileNameA(NULL, gamePath, MAX_PATH);
					strrchr(gamePath, '\\')[1] = 0;	//Remove EXE filename
				}
				init_mods();
			} else {
				printf("Debugger is not enabled. Start with /debug option to enable\n");
			}
            break;
        case DLL_PROCESS_DETACH:
			if (debugging) {
				deinit_mods();
			}
            break;
    }
    return TRUE;
}

