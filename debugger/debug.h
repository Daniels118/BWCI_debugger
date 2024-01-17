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

enum CatchEvent {
	EV_NONE,
	EV_SYSCALL,
	EV_SYSCALL_RET,
};

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
		bool exceptionMatched = false;

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
			this->globalsCount = 0;
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

class Watch {
	private:
		Expression* expression;
		bool enabled = true;

	public:
		Task* task;
		float oldValue = 0.0;
		float newValue = 0.0;
		bool matched = false;

		Watch(Task* task, Expression* expression) {
			this->task = task;
			this->expression = expression;
			expression->refCount++;
		}

		~Watch() {
			expression->refCount--;
		}

		std::string getKey() {
			if (task == NULL) {
				return "{0} " + expression->str;
			}
			return "{" + std::to_string(task->taskNumber) + "} ";
		}

		bool isEnabled() {
			return this->enabled;
		}

		void setEnabled(bool enabled) {
			if (enabled) {
				if (!this->enabled) {
					this->enabled = enabled;
					Var* val = evalExpression(this->task, this->expression);
					if (val != NULL) {
						this->oldValue = val->floatVal;
						this->newValue = val->floatVal;
					}
					matched = false;
				}
			} else {
				this->enabled = false;
			}
		}

		Expression* getExpression() {
			return this->expression;
		}
};

class Breakpoint {
	private:
		Expression* condition = NULL;
		bool enabled = true;

	public:
		std::string filename;
		DWORD lineno;
		Script* script;
		DWORD ip;
		DWORD targetHitCount = 0;
		DWORD hits = 0;
		bool triggerPoint = false;
		bool disabledByTrigger = false;
		bool deleteOnHit = false;
		Task* thread = NULL;

		std::list<std::string> commands;

		Breakpoint(std::string filename, DWORD lineno, Script* script, DWORD ip, Task* thread) {
			this->filename = filename;
			this->lineno = lineno;
			this->script = script;
			this->ip = ip;
			this->thread = thread;
		}

		~Breakpoint() {
			this->setCondition(NULL);
		}

		bool isEnabled() {
			return this->enabled;
		}

		void setEnabled(bool enabled) {
			if (enabled) {
				if (!this->enabled) {
					this->hits = 0;
					this->enabled = true;
					this->disabledByTrigger = false;
				}
			} else {
				this->enabled = false;
			}
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
};

typedef std::list<std::pair<DWORD, std::string>> ParserMessages;

const char* findFilenameByIp(DWORD ip);

const char* findStringData(std::string needle, const char* after, bool prefix);
size_t getOrDefineString(const char* str);

int getTotalInstructions();
int findInstruction(DWORD startIp, DWORD opcode);
int findInstructionIndex(const char* filename, const int linenumber);
Instruction* getCurrentInstruction(Task* task);
Instruction* getInstruction(int ip);

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

int getOrDeclareGlobalVar(const char* name, size_t size);
int declareGlobalVar(const char* name, size_t size);
int addLocalVar(Task* task, const char* name, float value, size_t size);

Task* getInnermostFrame(Task* task);
int getFrameDepth(Task* task);
std::vector<Task*> getBacktrace(Task* task);
Task* getParentFrame(Task* frame);
Task* getChildFrame(Task* frame);
std::vector<Task*> getThreads();
Task* getFrame(Task* thread);
Task* getThread(Task* task);
Task* getTaskById(int taskId);

void setSource(std::string filename, std::vector<std::string> lines);
void unsetSource(std::string filename);
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

std::list<Breakpoint*> getBreakpoints();
Breakpoint* setBreakpoint(std::string filename, DWORD lineno, DWORD ip, Task* thread, const char* condition);
bool setCondition(Breakpoint* breakpoint, const char* condition);
bool unsetBreakpoint(Breakpoint* breakpoint);
Breakpoint* getBreakpointByIndex(DWORD index);
Breakpoint* getBreakpointAtLine(std::string filename, DWORD line);
Breakpoint* getBreakpointAtAddress(int ip);

std::list<Watch*> getWatches();
Watch* addWatch(Task* task, const char* expression);
Watch* getWatchByIndex(DWORD index);
bool deleteWatch(Watch* watch);

void jump(Task* task, int ip);

bool stopThread(Task* thread);

bool updateCHL(const char* filename);

bool checkMessage(ParserMessages messages, DWORD minSeverity, std::string text);
void throwParserMessages(ParserMessages messages);

class Debugger {
	public:
		virtual void init() = 0;	//Called just once when the game has been initialized (during loading screen)
		virtual void start() = 0;	//Called every time a CHL has been loaded (when starting new game or loading saved game)
		virtual void term() = 0;	//Called just once when the program is being closed
		virtual void threadStarted(Task* task) = 0;
		virtual void threadResumed(Task* task) = 0;
		virtual void threadEnded(void* pThread, TaskInfo* info) = 0;
		virtual void breakpointHit(Task* task, Breakpoint* breakpoint) = 0;
		virtual void onCatchpoint(Task* task, int event) = 0;
		virtual void beforeInstruction(Task* task) = 0;
		virtual void beforeLine(Task* task) = 0;
		virtual void onPauseBeforeInstruction(Task* task) = 0;
		virtual void onPauseBeforeLine(Task* task) = 0;
		virtual void onException(Task* task, bool exception, std::list<Watch*> watches) = 0;
		virtual void onMessage(DWORD severity, const char* format, ...) = 0;
};

extern ScriptLibraryRDll ScriptLibraryR;
extern std::set<std::string> sourcePath;
extern Task* steppingThread;
extern Task* catchThread;
extern BYTE catchSysCalls[];
extern DWORD breakFromAddress;
extern int breakAfterLines;
extern int breakAfterInstructions;
extern int stepInMaxDepth;
extern bool pause;
extern std::stack<ParserMessages*> parseMessagesTraps;
extern int allowedThreadId;

extern bool gamePaused;

extern std::map<DWORD, std::string> scriptType_names;

extern const char* datatype_names[8];
extern char datatype_chars[8];
extern const char* vartype_names[4];

constexpr auto NOT_SET = 0;
constexpr auto ENABLED = 1;
constexpr auto DISABLED = 2;
