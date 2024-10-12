#pragma once

#include "ScriptLibraryR.h"

#include <string>
#include <list>
#include <stack>
#include <vector>
#include <map>
#include <set>

#include <windows.h>

#define DT_AUTODETECT -1
#define DT_ARRAY -2

class Breakpoint;
class LineBreakpoint;
class Watch;
class SyscallCatchpoint;
class CallCatchpoint;
class RunCatchpoint;

extern std::unordered_map<int, LineBreakpoint*> lineBreakpoints;
extern std::list<Watch*> watches;
extern SyscallCatchpoint* catchSysCalls[];
extern std::map<std::string, CallCatchpoint*> catchCallScripts;
extern std::map<std::string, RunCatchpoint*> catchRunScripts;

class VarDef {
	public:
		int id;
		std::string name;
		size_t size = 1;

		VarDef(int id, std::string name) {
			this->id = id;
			this->name = name;
		}
};

class Parameter {
	public:
		std::string name;
		int type;
		union {
			FLOAT floatVal;
			int intVal;
		};

		Parameter(std::string name, int type) {
			this->name = name;
			this->type = type;
			this->intVal = 0;
		}

		std::string toString() {
			if (type == DataTypes::DT_FLOAT || type == DataTypes::DT_COORDS || type == DataTypes::DT_VAR) {
				return std::to_string(floatVal);
			} else {
				return std::to_string(intVal);
			}
		}
};

class TaskInfo {
	public:
		int id;
		std::string name;
		std::vector<Parameter> parameters = std::vector<Parameter>();
		int lastStepLine = -1;
		int currentIp = -1;
		bool exceptionMatched = false;
		TaskInfo* thread = NULL;
		bool suspend = false;
		bool suspended = false;

		TaskInfo(int id, std::string name) {
			this->id = id;
			this->name = name;
		}

		std::string formatParameters() {
			std::string res = "";
			if (!parameters.empty()) {
				res = parameters[0].toString();
				for (size_t i = 1; i < parameters.size(); i++) {
					res += ", " + parameters[i].toString();
				}
			}
			return res;
		}
};

class Expression {
	public:
		std::string str;
		DWORD datatype;
		Script* script;
		int varId;
		int globalsCount;
		int start;
		int instructionAddress;
		size_t instructionsCount;

		int refCount = 0;

		Expression(std::string str, DWORD datatype, Script* script, int varId) {
			this->str = str;
			this->datatype = datatype;
			this->script = script;
			this->varId = varId;
			this->globalsCount = script != NULL ? script->globalsCount : varId;
			this->start = -1;
			this->instructionAddress = -1;
			this->instructionsCount = 0;
		}

		Expression(std::string str, DWORD datatype, Script* script, int globalsCount, int start, size_t instructionsCount, int instructionAddress) {
			this->str = str;
			this->datatype = datatype;
			this->script = script;
			this->varId = -1;
			this->globalsCount = globalsCount;
			this->start = start;
			this->instructionAddress = instructionAddress;
			this->instructionsCount = instructionsCount;
		}

		size_t getSize() {
			return sizeof(Expression) + instructionsCount * sizeof(Instruction);
		}
};

Var* evalExpression(Task* context, Expression* expr);


enum class BreakpointType {
	LINE, WATCH, SYSCALL, CALL, RUN
};


class Breakpoint {
private:
	static int nextId;

	int id;
	BreakpointType type;
	Expression* condition = NULL;

protected:
	bool enabled = false;	//Must be enabled in the child class constructor

public:
	DWORD targetHitCount = 0;
	DWORD hits = 0;
	bool triggerPoint = false;
	bool disabledByTrigger = false;
	bool deleteOnHit = false;
	bool temporary = false;

	std::list<std::string> commands;

	Breakpoint(BreakpointType type) {
		this->id = nextId++;
		this->type = type;
	}

	virtual ~Breakpoint() {
		this->setCondition(NULL);
	}

	int getId() {
		return id;
	}

	BreakpointType getType() {
		return type;
	}

	void setCondition(Expression* expr) {
		if (this->condition != NULL) {
			this->condition->refCount--;
		}
		this->condition = expr;
		if (expr != NULL) {
			expr->refCount++;
		}
	}

	Expression* getCondition() {
		return this->condition;
	}

	bool isEnabled() {
		return this->enabled;
	}

	virtual void setEnabled(bool enabled) = 0;
};


class LineBreakpoint : public Breakpoint {
public:
	std::string filename;
	DWORD lineno;
	Script* script;
	DWORD ip;
	Task* thread = NULL;

	LineBreakpoint(std::string filename, DWORD lineno, Script* script, DWORD ip, Task* thread)
		: Breakpoint(BreakpointType::LINE) {
		this->filename = filename;
		this->lineno = lineno;
		this->script = script;
		this->ip = ip;
		this->thread = thread;
		this->setEnabled(true);
	}

	~LineBreakpoint() {
		this->setEnabled(false);
	}

	void setEnabled(bool enabled) {
		if (enabled) {
			if (!this->enabled) {
				this->hits = 0;
				this->enabled = true;
				this->disabledByTrigger = false;
				lineBreakpoints[this->ip] = this;
			}
		} else {
			this->enabled = false;
			lineBreakpoints.erase(this->ip);
		}
	}
};


class Watch : public Breakpoint {
	public:
		Task* task;
		float oldValue = 0.0;
		float newValue = 0.0;
		bool matched = false;

		Watch(Task* task, Expression* expression)
			: Breakpoint(BreakpointType::WATCH) {
			this->task = task;
			this->setCondition(expression);
			this->setEnabled(true);
		}

		~Watch() {
			this->setEnabled(false);
		}

		void setEnabled(bool enabled) {
			if (enabled) {
				if (!this->enabled) {
					this->enabled = enabled;
					Var* val = evalExpression(this->task, this->getCondition());
					if (val != NULL) {
						this->oldValue = val->floatVal;
						this->newValue = val->floatVal;
					}
					matched = false;
					watches.push_back(this);
				}
			} else {
				this->enabled = false;
				watches.remove(this);
			}
		}
};


class SyscallCatchpoint : public Breakpoint {
private:
	int syscall = -1;

public:
	SyscallCatchpoint(int syscall)
		: Breakpoint(BreakpointType::SYSCALL) {
		this->syscall = syscall;
		this->setEnabled(true);
	}

	~SyscallCatchpoint() {
		this->setEnabled(false);
	}

	int getSyscall() {
		return this->syscall;
	}

	const char* getSyscallName() {
		return NativeFunctions::NativeFunctionNames[this->syscall];
	}

	void setEnabled(bool enabled) {
		this->enabled = enabled;
		catchSysCalls[this->syscall] = enabled ? this : NULL;
	}
};

class CallCatchpoint : public Breakpoint {
private:
	std::string script;

public:
	CallCatchpoint(std::string script)
		: Breakpoint(BreakpointType::CALL) {
		this->script = script;
		this->setEnabled(true);
	}

	~CallCatchpoint() {
		this->setEnabled(false);
	}

	std::string getScript() {
		return this->script;
	}

	void setEnabled(bool enabled) {
		this->enabled = enabled;
		if (enabled) {
			catchCallScripts[script] = this;
		} else {
			catchCallScripts.erase(script);
		}
	}
};

class RunCatchpoint : public Breakpoint {
private:
	std::string script;

public:
	RunCatchpoint(std::string script)
		: Breakpoint(BreakpointType::RUN) {
		this->script = script;
		this->setEnabled(true);
	}

	~RunCatchpoint() {
		this->setEnabled(false);
	}

	std::string getScript() {
		return this->script;
	}

	void setEnabled(bool enabled) {
		this->enabled = enabled;
		if (enabled) {
			catchRunScripts[script] = this;
		} else {
			catchRunScripts.erase(script);
		}
	}
};


typedef std::list<std::pair<DWORD, std::string>> ParserMessages;

void getObjectProperty(DWORD objId, int prop, Var* out);
int getObjectType(DWORD objId);
int getObjectSubType(DWORD objId);
const char* getTypeName(int type);
const char* getSubTypeName(int type, int subType);
void getObjectPosition(DWORD objId, float coords[]);

const char* findFilenameByIp(DWORD ip);

const char* findStringData(std::string needle, const char* after, bool prefix);
size_t getOrDefineString(const char* str);

int getTotalInstructions();
int findInstruction(DWORD startIp, DWORD opcode);
int findInstructionIndex(const char* filename, const int linenumber);
Instruction* getCurrentInstruction(Task* task);
Instruction* getInstruction(int ip);
TaskInfo* getTaskInfo(Task* task);

std::list<Script*> getScripts();
Script* findScriptByIp(DWORD ip);
Script* getScriptById(int scriptId);
Script* getScriptByName(std::string name);
Script* getTaskScript(Task* task);

int getGlobalVarsCount();
std::list<VarDef> getGlobalVarDefs();
int getLocalVarsCount(Task* task);

int getGlobalVarId(const char* name, int index);
int getLocalVarId(Script* script, const char* name, int index);
int getVarId(Script* script, const char* name);

Var* getVar(Task* task, const char* name);
Var* getVarById(Task* task, int id);
Var* getBaseAndIndex(Task* task, int id, int* index);
Var* getGlobalVarById(int id);
Var* getGlobalVar(const char* name);
Var* getLocalVar(Task* task, const char* name);

bool varIsGlobal(Var* var);
bool varIsLocal(Var* var, Task* task);
bool varIsArray(Task* task, Var* var);
int getVarSize(Task* task, Var* var);

int getOrDeclareGlobalVar(const char* name, size_t size, float value);
int declareGlobalVar(const char* name, size_t size, float value);
int addLocalVar(Task* task, const char* name, float value, size_t size);

Task* getInnermostFrame(Task* task);
Task* getFrameAt(Task* task, int depth);
int getFrameDepth(Task* task);
std::vector<Task*> getBacktrace(Task* task);
Task* getParentFrame(Task* frame);
Task* getParentFrame(Task* task, int depth);
Task* getChildFrame(Task* frame);
Task* getChildFrame(Task* task, int depth);
std::vector<Task*> getThreads();
Task* getThread(Task* task);
Task* getTaskById(int taskId);

void setSource(std::string filename, std::vector<std::string> lines);
void unsetSource(std::string filename);
void unsetMissingSources();
std::string findSourceFile(std::string filename);
std::vector<std::string> getSource(std::string filename);
std::string getSourceLine(std::string filename, int lineno);
std::string getCurrentSourceLine(Task* task);

void formatVar(Script* script, int id, char* buffer);
void formatInstruction(Script* script, Instruction* instr, char* buffer);
void formatTaskVar(Task* task, int id, char* buffer);
void formatTaskInstruction(Task* task, Instruction* instr, char* buffer);
void formatTaskParameters(Task* task, char* buffer);

int parseCode(const char* code, const char* FileName);
Expression* getCompiledExpression(Script* script, std::string expression, int datatype);
Var* evalExpression(Task* context, Expression* expr);
Var* evalString(Task* context, std::string expression, int& datatype);
bool deleteScriptByName(const char* name);

void suspendThread(int threadId);
void resumeThread(int threadId);

std::vector<Breakpoint*> getBreakpoints();
Breakpoint* getBreakpointById(int id);
Breakpoint* getBreakpointByIndex(DWORD index);
bool unsetBreakpoint(Breakpoint* breakpoint);

LineBreakpoint* setLineBreakpoint(std::string filename, DWORD lineno, DWORD ip, Task* thread, const char* condition);
bool setCondition(Breakpoint* breakpoint, const char* condition);
LineBreakpoint* getBreakpointAtLine(std::string filename, DWORD line);
LineBreakpoint* getBreakpointAtAddress(int ip);
Watch* addWatch(Task* task, const char* expression);
Watch* getWatchByExpression(Task* task, std::string expr);
SyscallCatchpoint* setSyscallCatchpoint(int syscall);
SyscallCatchpoint* getSyscallCatchpoint(int syscall);
CallCatchpoint* setCallCatchpoint(std::string script);
CallCatchpoint* getCallCatchpoint(std::string script);
RunCatchpoint* setRunCatchpoint(std::string script);
RunCatchpoint* getRunCatchpoint(std::string script);

void jump(Task* task, int ip);

bool stopThread(Task* thread);

bool updateCHL(const char* filename, bool stopAllInChangedFiles);

bool checkMessage(ParserMessages messages, DWORD minSeverity, std::string text);
void throwParserMessages(ParserMessages messages);

class Debugger {
	public:
		virtual void init() = 0;	//Called just once when the game has been initialized (during loading screen)
		virtual void start() = 0;	//Called every time a CHL has been loaded (when starting new game or loading saved game)
		virtual void term() = 0;	//Called just once when the program is being closed
		virtual void threadStarted(Task* task) = 0;
		virtual void threadRestored(Task* task) = 0;
		virtual void threadPaused(Task* task) = 0;
		virtual void taskPoll(Task* task) = 0;
		virtual void threadResumed(Task* task) = 0;
		virtual void threadEnded(void* pThread, TaskInfo* info) = 0;
		virtual void onBreakpoint(Task* task, LineBreakpoint* breakpoint) = 0;
		virtual void onCatchpoint(Task* task, Breakpoint* catchpoints[], size_t count) = 0;
		virtual void beforeInstruction(Task* task) = 0;
		virtual void beforeLine(Task* task) = 0;
		virtual void onPauseBeforeInstruction(Task* task) = 0;
		virtual void onPauseBeforeLine(Task* task) = 0;
		virtual void onMessage(DWORD severity, const char* format, ...) = 0;
};

extern bool asyncMode;
extern std::set<std::string> sourcePath;
extern Task* steppingThread;
extern DWORD breakFromAddress;
extern int breakAfterLines;
extern int breakAfterInstructions;
extern int stepInMaxDepth;
extern BYTE stepInExceptionHandler;
extern bool pause;
extern std::stack<ParserMessages*> parseMessagesTraps;
extern int allowedThreadId;

extern bool gamePaused;

extern std::unordered_map<std::string, int> ScriptObjectTypes;
extern std::map<std::string, int> ObjectProperties;
