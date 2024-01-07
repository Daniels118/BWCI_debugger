#pragma once

#include "ScriptLibraryR.h"
#include "debug.h"
#include "utils.h"

#include <iostream>
#include <queue>

class Display {
	public:
		std::string expression;
		int datatype;
		bool enabled = true;

		Display(std::string expression, int datatype) {
			this->expression = expression;
			this->datatype = datatype;
		}
};

class UserCommand {
	public:
		std::list<std::string> commands;
};

class Gdb : public Debugger {
	private:
		static const int BUFFER_SIZE = 1024;
		static const int MAX_ARGS = 64;

		static char buffer[BUFFER_SIZE];
		static char* argv[MAX_ARGS];

		static std::queue<std::string> commandQueue;

		static Breakpoint* lastHitBreakpoint;

		static char lastPrintedFile[256];
		static int firstPrintedLine;
		static int lastPrintedLine;

		static Task* currentFrame;
		static int compiledThreadId;
		static int resumeThreadId;

		static std::list<Display*> displays;

		static std::map<std::string, UserCommand> userCommands;

		static int maxPrintElements;

	public:
		Gdb() {
			char* cmd = GetCommandLineA();
			strcpy(buffer, cmd);
			int argc = splitArgs(buffer, ' ', argv, MAX_ARGS);
			char* script = getArgVal(argv, argc, "/gdb:script");
			if (script != NULL) {
				commandQueue.push("source " + std::string(script));
			}
		}

		void init() {
			if (GetConsoleWindow() == NULL) {
				AllocConsole();
				FILE* t;
				t = freopen("CONOUT$", "w", stdout);
				t = freopen("CONIN$", "r", stdin);
			}
			if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
				printf("ERROR: cannot set control handler\n");
			}
		}

		void start() {
			printf("\n");
			printf("Debugging using gdb interface.\n");
			printf("Press CTRL+C to break the execution and get a prompt. For help, type \"help\".\n");
		}

		void threadStarted(Task* thread) {
			printf("New Thread %i \"%s\"\n", thread->taskNumber, thread->name);
		}

		void threadResumed(Task* thread) {
			Task* frame = getInnermostFrame(thread);
			Instruction* instr = getCurrentInstruction(frame);
			printf("Thread %i \"%s\" resumed, currently in \"%s\" at %s:%i\n", thread->taskNumber, thread->name, frame->name, frame->filename, instr->linenumber);
		}

		void threadEnded(Task* thread) {
			if (thread == catchThread) {
				catchThread = NULL;
			}
			printf("Thread %i \"%s\" ended\n", thread->taskNumber, thread->name);
			if (thread->taskNumber == compiledThreadId) {
				allowedThreadId = resumeThreadId;	//Resume from previous thread and
				pause = true;						//  stop when previous thread resumes
			}
		}

		void breakpointHit(Task* task, Breakpoint* breakpoint) {
			lastHitBreakpoint = breakpoint;
			char args[512];
			formatTaskParameters(task, args);
			printf("Breakpoint, %s (%s) at %s:%i\n", task->name, args, task->filename, breakpoint->lineno);
			if (breakpoint->deleteOnHit) {
				unsetBreakpoint(breakpoint);
				printf("Breakpoint deleted.\n");
			} else if (breakpoint->targetHitCount) {
				printf("Breakpoint disabled.\n");
			}
			currentFrame = task;
			for (std::string cmd : breakpoint->commands) {
				commandQueue.push(cmd);
			}
			printDisplays(task);
			printCurrentLine(task);
			readAndExecuteCommand(task);
		}

		void onCatchpoint(Task* task, int event) {
			Instruction* instr = getCurrentInstruction(task);
			if (event == EV_SYSCALL) {
				printf("Catchpoint (call to syscall '%s')\n", NativeFunctions[instr->intVal]);
			} else if (event == EV_SYSCALL_RET) {
				printf("Catchpoint (returned from syscall '%s')\n", NativeFunctions[instr->intVal]);
			}
			printDisplays(task);
			printCurrentLine(task);
			readAndExecuteCommand(task);
		}

		void beforeInstruction(Task* task) {
			printCurrentInstruction(task);
		}

		void beforeLine(Task* task) {
			printCurrentLine(task);
		}

		void onPauseBeforeInstruction(Task* task) {
			checkTempScriptEnded();
			Instruction* instruction = getCurrentInstruction(task);
			printDisplays(task);
			printCurrentInstruction(task);
			readAndExecuteCommand(task);
		}

		void onPauseBeforeLine(Task* task) {
			checkTempScriptEnded();
			allowedThreadId = 0;
			Instruction* instruction = getCurrentInstruction(task);
			printDisplays(task);
			printCurrentLine(task);
			readAndExecuteCommand(task);
		}

		void onException(Task* task, bool exception, std::list<Watch*> watches) {
			for (Watch* watch : watches) {
				printf("Old value = %f\n", watch->oldValue);
				printf("New value = %f\n", watch->newValue);
				printf("Watchpoint: %s\n", watch->expression->str.c_str());
			}
			if (exception) {
				printf("Exception in Thread %i\n", catchThread->taskNumber);
			}
			printDisplays(task);
			printCurrentLine(task);
			readAndExecuteCommand(task);
		}

		void onMessage(DWORD severity, const char* format, ...) {
			if (severity != 0) {
				va_list args;
				va_start(args, format);
				vprintf(format, args);
				printf("\n");
				va_end(args);
			}
		}

	private:
		static BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
			switch (fdwCtrlType) {
			case CTRL_C_EVENT:
				if (!commandQueue.empty()) {
					while (!commandQueue.empty()) {
						commandQueue.pop();
					}
					printf("\nScript execution interrupted.\n");
				}
				printf("\nPaused.\n");
				if (*ScriptLibraryR.pTaskList != NULL) {
					pause = true;
				} else {
					readAndExecuteCommand(NULL);
				}
				return TRUE;
			default:
				return FALSE;
			}
		}

		static void checkTempScriptEnded() {
			if (compiledThreadId != 0 && !ScriptLibraryR.taskExists(compiledThreadId)) {
				compiledThreadId = 0;
				resumeThreadId = 0;
				if (deleteScriptByName("_gdb_expr_")) {
					unsetSource("__debugger_compile");
					printf("Script '_gdb_expr_' deleted.\n");
				}
			}
		}

		static void printDisplays(Task* task) {
			Script* script = getTaskScript(task);
			ParserMessages messages;
			int i = 1;
			for (Display* display : displays) {
				if (display->enabled) {
					parseMessagesTraps.push(&messages);
					Expression* expr = getCompiledExpression(script, display->expression, display->datatype);
					parseMessagesTraps.pop();
					if (expr == NULL) {
						if (!checkMessage(messages, 0, "Unable to find variable")) {
							printf("%i: %s\n", i, display->expression.c_str());
							throwParserMessages(messages);
						}
					} else {
						Var* val = evalExpression(task, expr);
						if (val != NULL) {
							if (expr->datatype == DT_FLOAT) {
								printf("%i: %s = %f\n", i, display->expression.c_str(), val->floatVal);
							} else if (expr->datatype == DT_INT) {
								printf("%i: %s = %i\n", i, display->expression.c_str(), val->intVal);
							} else if (expr->datatype == DT_BOOLEAN) {
								printf("%i: %s = %s\n", i, display->expression.c_str(), val->intVal ? "true" : "false");
							}
						}
					}
				}
				i++;
			}
		}

		static void printFrame(Task* tFrame, int index) {
			if (index < 0) {
				index = getFrameDepth(getInnermostFrame(tFrame)) - getFrameDepth(tFrame);
			}
			char args[512];
			formatTaskParameters(tFrame, args);
			Instruction& instruction = *getCurrentInstruction(tFrame);
			printf("#%i: %s (%s) at %s:%i\n", index, tFrame->name, args, tFrame->filename, instruction.linenumber);
		}

		static void printCurrentInstruction(Task* task) {
			char buffer[1024];
			Instruction* instruction = getCurrentInstruction(task);
			formatTaskInstruction(task, instruction, buffer);
			printf("%i: %s\n", task->ip, buffer);
			firstPrintedLine = 0;
			lastPrintedLine = 0;
		}
		
		static void printCurrentLine(Task* task) {
			Instruction* instruction = getCurrentInstruction(task);
			std::string pLine = getCurrentSourceLine(task);
			if (pLine != "") {
				printf("%i: %s\n", instruction->linenumber, pLine.c_str());
			} else {
				printCurrentInstruction(task);
			}
			firstPrintedLine = 0;
			lastPrintedLine = 0;
		}

		static void moveFrame(int n, bool silent) {
			if (currentFrame == NULL) {
				printf("No frame selected.\n");
			} else {
				Task* task = currentFrame;
				while (n > 0 && task != NULL) {
					currentFrame = task;
					task = getParentFrame(task);
					n--;
				}
				while (n < 0 && task != NULL) {
					currentFrame = task;
					task = getChildFrame(task);
					n++;
				}
				if (!silent) {
					printFrame(currentFrame, -1);
				}
			}
		}

		static bool prompt(const char* format, ...) {
			if (commandQueue.empty()) {
				va_list args;
				va_start(args, format);
				vprintf(format, args);
				va_end(args);
			}
			return readCommand();
		}

		static bool readCommand() {
			if (commandQueue.empty()) {
				if (fgets(buffer, BUFFER_SIZE, stdin) != NULL) {
					buffer[strcspn(buffer, "\r\n")] = 0;
					return true;
				}
			} else {
				std::string cmd = commandQueue.front();
				commandQueue.pop();
				strcpy(buffer, cmd.c_str());
				//printf("%s\n", buffer);		//Echo ON
				return true;
			}
			return false;
		}

		static void readAndExecuteCommand(Task* task) {
			currentFrame = task;
			while (true) {
				if (prompt("(gdb) ")) {
					bool cont = processCommand();
					if (cont) {
						break;
					}
				} else {
					printf("Failed to read command.\n");
					break;
				}
			}
		}

		static bool inArray(const int value, char** argv, int argc) {
			for (int i = 0; i < argc; i++) {
				int t = atoi(argv[i]);
				if (value == t) {
					return true;
				}
			}
			return false;
		}

		static bool inArray(const char* value, char** argv, int argc) {
			for (int i = 0; i < argc; i++) {
				if (streq(argv[i], value)) {
					return true;
				}
			}
			return false;
		}

		static bool abbrev(const char* str, const char* prefix, size_t nMin) {
			return strncmp(str, prefix, MAX(strlen(str), nMin)) == 0;
		}

		static int usprintf(char* bufferOut, const char* format, int argc, char** argv) {
			const char* src = format;
			char* dst = bufferOut;
			int argIndex = 0;
			for (char c = *src; c != 0; src++, dst++, c = *src) {
				if (c == '\\') {
					c = *(++src);
					if (c == 0) {
						printf("Unexpected end of string.\n");
						return -1;
					} else if (c == 'n') {
						*dst = '\n';
					} else if (c == 't') {
						*dst = '\t';
					} else {
						*dst = c;
					}
				} else if (c == '%') {
					if (argIndex >= argc) {
						printf("The number of parameters doesn't match with the placeholders.\n");
						return -1;
					}
					c = *(++src);
					if (c == 'i' || c == 'f') {
						int datatype = DT_FLOAT;
						Var* val = evalString(currentFrame, argv[argIndex], datatype);
						if (val == NULL) {
							printf("Failed to evaluate '%s'.\n", argv[argIndex]);
							return -1;
						}
						if (c == 'i') {
							dst += sprintf(dst, "%i", (int)val->floatVal) - 1;
						} else if (c == 'f') {
							dst += sprintf(dst, "%f", val->floatVal) - 1;
						}
					} else {
						printf("Invalid format specifier.\n");
						return -1;
					}
					argIndex++;
				} else {
					*dst = c;
				}
			}
			*dst = 0;
			if (argIndex != argc) {
				printf("The number of parameters doesn't match with the placeholders.\n");
				return -1;
			}
			return dst - bufferOut;
		}

		static void uprint(char* rawBuffer, const char* prefix, const char* suffix) {
			const char* format = "";
			int datatype = DT_AUTODETECT;
			char* expression = argv[1];
			if (argv[1][0] == '/') {
				format = argv[1];
				expression = argv[2];
				if (streq(format, "/f")) {
					datatype = DT_FLOAT;
				} else if (streq(format, "/d")) {
					datatype = DT_INT;
				} else if (streq(format, "/b")) {
					datatype = DT_BOOLEAN;
				} else {
					printf("Invalid format. Valid formats are /f, /d and /b.\n");
					return;
				}
			}
			expression = rawBuffer + (expression - buffer);
			//rejoinArgs(argv, argc, expression, NULL);
			Var* result = getVar(currentFrame, expression);
			if (result != NULL) {
				datatype = varIsArray(currentFrame, result) ? DT_ARRAY : DT_FLOAT;
			} else {
				result = evalString(currentFrame, expression, datatype);
			}
			if (result != NULL) {
				if (datatype == DT_FLOAT) {
					printf("%s%f%s", prefix, result->floatVal, suffix);
				} else if (datatype == DT_INT) {
					printf("%s%i%s", prefix, (int)result->floatVal, suffix);
				} else if (datatype == DT_BOOLEAN) {
					printf("%s%s%s", prefix, result->floatVal != 0.0 ? "true" : "false", suffix);
				} else if (datatype == DT_ARRAY) {
					const int count = getVarSize(currentFrame, result);
					printf("%s{%f", prefix, result->floatVal);
					result++;
					for (int i = 1; i < count; i++, result++) {
						if (i >= maxPrintElements) {
							printf(", ...");
							break;
						}
						printf(", %f", result->floatVal);
					}
					printf("}%s", suffix);
				} else {
					printf("Can't display value of type %s\n", datatype_names[datatype]);
				}
			}
		}

		static bool processCommand() {
			char rawBuffer[BUFFER_SIZE];
			strcpy(rawBuffer, buffer);
			int argc = splitArgs(buffer, ' ', argv, MAX_ARGS);
			char* cmd = argv[0];
			if (strlen(cmd) == 0) {
				return false;
			//################################################################################################## ADVANCE
			} else if (streq(cmd, "advance")) {
				if (currentFrame == NULL) {
					printf("No frame selected.");
					return false;
				}
				int ip = -1;
				const char* file = currentFrame->filename;
				if (argc >= 2) {
					const char* arg = argv[1];
					if (arg[0] == '*') {
						ip = atoi(arg + 1);
						if (ip < 0 || ip >= getTotalInstructions()) {
							printf("Invalid instruction address: %i\n", ip);
							return false;
						}
					} else {
						int line = atoi(arg);
						ip = findInstructionIndex(file, line);
						if (ip == -1) {
							printf("Invalid line %i in file %s\n", line, file);
							return false;
						} else if (ip == -2) {
							printf("File %s not found\n", file);
							return false;
						}
					}
					breakFromAddress = ip;
					breakAfterLines = 0;
					steppingThread = getThread(currentFrame);
					stepInMaxDepth = 9999;
					return true;
				} else {
					const int count = getTotalInstructions();
					ip = currentFrame->ip;
					Instruction* instr = getInstruction(ip);
					const DWORD currentLine = instr->linenumber;
					for (ip++; ip < count; ip++) {
						instr = getInstruction(ip);
						if (instr->linenumber > currentLine) {
							breakFromAddress = ip;
							breakAfterLines = 0;
							steppingThread = getThread(currentFrame);
							stepInMaxDepth = 9999;
							return true;
						} else if (instr->opcode == END) {
							break;
						}
					}
					printf("No more lines in current script.\n");
					return false;
				}
			//################################################################################################## BACKTRACE
			} else if (streq(cmd, "bt") || streq(cmd, "backtrace") || streq(cmd, "where")) {
				if (currentFrame != NULL) {
					Task* thread = getThread(currentFrame);
					printf("Thread %i\n", thread->taskNumber);
					std::vector<Task*> backtrace = getBacktrace(currentFrame);
					int start = 0;
					int end = backtrace.size();
					if (argc >= 2) {
						int n = atoi(argv[1]);
						int frameIndex = backtrace.size() - 1 - getFrameDepth(currentFrame);
						if (n > 0) {
							start = frameIndex - n;
							end = frameIndex;
						} else if (n < 0) {
							start = frameIndex + 1;
							end = frameIndex + 1 - n;
						}
						if (start < 0) start = 0;
						if (end > (int)backtrace.size()) end = backtrace.size();
					}
					for (int i = start; i < end; i++) {
						printFrame(backtrace[i], i);
					}
				} else {
					printf("No active task\n");
				}
				return false;
			//################################################################################################## BREAK, TBREAK
			} else if (abbrev(cmd, "break", 1) || streq(cmd, "tbreak")) {
				int targetHitCount = streq(cmd, "tbreak") ? 1 : 0;
				const char* file = NULL;
				int line = -1;
				int ip = -1;
				Task* thread = NULL;
				const char* sCondition = NULL;
				if (argc == 1) {
					//break
					//  set breakpoint at next instruction
					if (currentFrame != NULL) {
						file = currentFrame->filename;
						line = getCurrentInstruction(currentFrame)->linenumber + 1;
					}
				} else {
					//break [file:]line [thread threadId] [if expr]
					//  set breakpoint at line number [in file] [for threadId] [if condition matched]
					const char* sThreadId = getArgVal(argv, argc, "thread");
					if (sThreadId != NULL) {
						int threadId = atoi(sThreadId);
						std::vector<Task*> threads = getThreads();
						if (threadId >= 1 && threadId <= (int)threads.size()) {
							thread = threads[threadId - 1];
						} else {
							printf("Invalid thread ID\n");
							return false;
						}
					}
					sCondition = getArgVal(argv, argc, "if");
					if (sCondition != NULL) {
						sCondition = rawBuffer + (sCondition - buffer);
						//rejoinArgs(argv, argc, sCondition, NULL);
					}
					argc = splitArgs(argv[1], ':', argv, MAX_ARGS);
					char* sLine = argv[argc - 1];
					if (sLine[0] == '+' || sLine[0] == '-') {
						//Relative address
						Instruction* instruction = getCurrentInstruction(currentFrame);
						if (instruction->linenumber == 0) {
							printf("Cannot determine current line number\n");
							return false;
						}
						int val = atoi(sLine);
						line = instruction->linenumber + val;
					} else if (sLine[0] == '*') {
						ip = atoi(sLine + 1);
						if (ip >= 0 && ip < getTotalInstructions()) {
							Instruction* instruction = getInstruction(ip);
							file = findFilenameByIp(ip);
							line = instruction->linenumber;
						} else {
							printf("Invalid instruction address: %i\n", ip);
							return false;
						}
					} else {
						line = atoi(sLine);
						if (line == 0) {
							Script* script = getScriptByName(sLine);
							if (script != NULL) {
								ip = script->instructionAddress;
								file = script->filename;
								line = getInstruction(ip)->linenumber;
							} else {
								printf("Script %s not found\n", sLine);
							}
						}
					}
					if (argc == 2) {
						file = argv[0];
					} else {
						file = currentFrame != NULL ? currentFrame->filename : NULL;
					}
				}
				if (ip < 0 && line > 0) {
					if (file != NULL) {
						ip = findInstructionIndex(file, line);
						if (ip == -1) {
							printf("Cannot set breakpoint on line %i in file %s\n", line, file);
							return false;
						} else if (ip == -2) {
							printf("File %s not found\n", file);
							return false;
						}
					} else {
						printf("File not set\n");
						return false;
					}
				}
				if (file != NULL && line > 0 && ip >= 0) {
					Breakpoint* breakpoint = setBreakpoint(file, line, ip, thread, sCondition);
					if (breakpoint != NULL) {
						breakpoint->targetHitCount = targetHitCount;
						printf("Breakpoint at %i from %s (%i)\n", line, file, ip);
					}
				} else {
					printf("Invalid breakpoint\n");
				}
				return false;
			//################################################################################################## CATCH
			} else if (streq(cmd, "catch")) {
				if (argc < 2) {
					catchThread = NULL;
					printf("Exception catching disabled\n");
				} else {
					const char* arg = argv[1];
					if (streq(arg, "exception")) {
						if (currentFrame == NULL) {
							printf("No active task.\n");
							return false;
						}
						catchThread = getThread(currentFrame);
						printf("Exception catching enabled for current thread\n");
					} else if (streq(arg, "syscall")) {
						for (int j = 2; j < argc; j++) {
							arg = argv[j];
							for (int i = 0; i < NATIVE_COUNT; i++) {
								if (streq(arg, NativeFunctions[i])) {
									catchSysCalls[i] = true;
								}
							}
						}
					} else {
						printf("Invalid event\n");
					}
				}
				return false;
			//################################################################################################## CLEAR
			} else if (streq(cmd, "clear")) {
				int ip = -1;
				if (argc == 1) {
					//delete breakpoints at next instruction
					if (currentFrame == NULL) {
						printf("No active task.\n");
						return false;
					}
					ip = currentFrame->ip;
				} else if (argc == 2) {
					argc = splitArgs(argv[1], ':', argv, MAX_ARGS);
					char* file;
					if (argc == 2) {
						file = argv[0];
					} else if (currentFrame == NULL) {
						printf("No active task.\n");
						return false;
					} else {
						file = currentFrame->filename;
					}
					char* arg = argv[argc - 1];
					if (arg[0] == '*') {
						ip = atoi(arg + 1);
						if (ip < 0 || ip >= getTotalInstructions()) {
							printf("Invalid instruction address: %i\n", ip);
							return false;
						}
					} else {
						int line = atoi(arg);
						ip = findInstructionIndex(file, line);
						if (ip == -1) {
							printf("Invalid line %i in file %s\n", line, file);
							return false;
						} else if (ip == -2) {
							printf("File %s not found\n", file);
							return false;
						}
					}
				}
				Breakpoint* breakpoint = getBreakpointAtAddress(ip);
				if (breakpoint != NULL) {
					unsetBreakpoint(breakpoint);
					printf("Breakpoint removed\n");
				} else {
					printf("Breakpoint not found\n");
				}
				return false;
			//################################################################################################## COMMANDS
			} else if (streq(cmd, "commands")) {
				Breakpoint* breakpoints[64];
				int nBreak = 0;
				if (argc < 2) {
					int index = getBreakpoints().size() - 1;
					if (index < 0) {
						printf("No breakpoint set.");
						return false;
					}
					breakpoints[nBreak++] = getBreakpointByIndex(index);
				} else {
					for (int i = 1; i < argc; i++) {
						int index = atoi(argv[i]) - 1;
						Breakpoint* breakpoint = getBreakpointByIndex(index);
						if (breakpoint != NULL) {
							breakpoints[nBreak++] = breakpoint;
						} else {
							printf("Breakpoint %i not found\n", index);
						}
					}
				}
				std::list<std::string> commands;
				while (prompt(">")) {
					if (streq(buffer, "end")) break;
					commands.push_back(buffer);
				}
				for (int i = 0; i < nBreak; i++) {
					Breakpoint* breakpoint = breakpoints[i];
					breakpoint->commands = commands;
				}
				return false;
			//################################################################################################## COMPILE
			} else if (streq(cmd, "compile")) {
				if (argc >= 2) {
					if (resumeThreadId != 0) {
						printf("A compiled code is already running.\n");
						return false;
					}
					const char* type = argv[1];
					bool prnt = false;
					int sepIndex = getArgIndex(argv, argc, "--");
					int optc = sepIndex >= 0 ? sepIndex : 2;
					bool raw = getArgFlag(argv, optc, "-raw");
					const char* expr = NULL;
					const int exprIndex = sepIndex >= 0 ? sepIndex + 1 : 2;
					if (exprIndex < argc) {
						expr = argv[exprIndex];
						expr = rawBuffer + (expr - buffer);
						//argc = rejoinArgs(argv, argc, expr, NULL);
					}
					if (streq(type, "print")) {
						std::string cmd = "p " + std::string(expr);
						strcpy(buffer, cmd.c_str());
						processCommand();
						return false;
					} else {
						std::vector<std::string> lines;
						if (!raw) {
							lines.push_back("begin script _gdb_expr_");
							lines.push_back("start");
						}
						if (streq(type, "code")) {
							if (expr != NULL) {
								lines.push_back(expr);
							} else {
								while (prompt(">")) {
									if (streq(buffer, "end")) break;
									lines.push_back(buffer);
								}
							}
						} else if (streq(type, "file")) {
							if (expr == NULL) {
								printf("Expected filename.\n");
								return false;
							}
							std::string absFilename = searchPaths(sourcePath, expr);
							if (absFilename == "") {
								printf("File not found.\n");
								return false;
							} else {
								auto filelines = readFile(absFilename);
								lines.insert(lines.end(), filelines.begin(), filelines.end());
							}
						}
						if (!raw) {
							lines.push_back("end script _gdb_expr_");
						}
						std::string code = "";
						for (auto line : lines) {
							code += line + "\n";
						}
						int r = parseCode(code.c_str(), "__debugger_compile");
						if (r == 0) {
							Script* script = getScriptByName("_gdb_expr_");
							if (script == NULL) {
								printf("Cannot find script '_gdb_expr_'.\n");
							} else {
								setSource("__debugger_compile", lines);
								if (currentFrame != NULL) {
									resumeThreadId = getThread(currentFrame)->taskNumber;
								}
								compiledThreadId = ScriptLibraryR.StartScript(0, "_gdb_expr_", -1);
								allowedThreadId = compiledThreadId;
								return true;
							}
						}
						return false;
					}
				}
			//################################################################################################## COND
			} else if (abbrev(cmd, "condition", 4)) {
				if (argc >= 2) {
					int index = atoi(argv[1]) - 1;
					Breakpoint* breakpoint = getBreakpointByIndex(index);
					if (breakpoint != NULL) {
						if (argc >= 3) {
							const char* sCond = argv[2];
							sCond = rawBuffer + (sCond - buffer);
							//rejoinArgs(argv, argc, sCond, NULL);
							setCondition(breakpoint, sCond);
							printf("Condition set\n");
						} else {
							setCondition(breakpoint, NULL);
							printf("Condition removed from breakpoint\n");
						}
					} else {
						printf("Breakpoint not found\n");
					}
					return false;
				}
			//################################################################################################## CONTINUE
			} else if (abbrev(cmd, "continue", 1) || streq(cmd, "fg")) {
				//continue running the program
				if (argc == 2 && lastHitBreakpoint != NULL) {
					lastHitBreakpoint->targetHitCount = atoi(argv[1]);
					lastHitBreakpoint->hits = 0;
				}
				printf("Continuing.\n");
				return true;
			//################################################################################################## DEFINE
			} else if (streq(cmd, "define")) {
				if (argc == 2) {
					const char* name = argv[1];
					auto& ucmd = userCommands[name];
					ucmd.commands.clear();
					while (prompt(">")) {
						if (streq(buffer, "end")) break;
						ucmd.commands.push_back(buffer);
					}
					return false;
				}
			//################################################################################################## DELETE
			} else if (abbrev(cmd, "delete", 1)) {
				if (argc == 1) {
					prompt("Delete all breakpoints? (y or n) ");
					if (streq(buffer, "y")) {
						for (Breakpoint* breakpoint : getBreakpoints()) {
							unsetBreakpoint(breakpoint);
						}
					}
					return false;
				} else if (argc == 3 && abbrev(argv[1], "display", 4)) {
					int index = atoi(argv[1]) - 1;
					if (index < 0 || index >= (int)displays.size()) {
						printf("Invalid index.\n");
					} else {
						auto it = displays.begin();
						std::advance(it, index);
						Display* display = *it;
						displays.erase(it);
						delete display;
					}
					return false;
				} else {
					int index = atoi(argv[1]) - 1;
					if (index < 0) {
						printf("Invalid index\n");
						return false;
					}
					auto breakpoints = getBreakpoints();
					if (index < (int)breakpoints.size()) {
						Breakpoint* breakpoint = getBreakpointByIndex(index);
						unsetBreakpoint(breakpoint);
					} else {
						index -= breakpoints.size();
						auto watches = getWatches();
						if (index < (int)watches.size()) {
							Watch* watch = getWatchByIndex(index);
							deleteWatch(watch);
						} else {
							index -= watches.size();
							for (int i = 0; i < NATIVE_COUNT; i++) {
								if (catchSysCalls[i]) {
									if (index-- == 0) {
										catchSysCalls[i] = false;
									}
								}
							}
							if (index >= 0) {
								printf("Breakpoint not found\n");
							}
						}
					}
					return false;
				}
			//################################################################################################## DETACH
			} else if (streq(cmd, "detach")) {
				printf("Command not implemented.\n");	//...and will never be!
				return false;
			//################################################################################################## DIRECTORY
			} else if (abbrev(cmd, "directory", 3)) {
				if (argc >= 2) {
					//dir names
					//  add directory names to front of source path
					for (int i = 1; i < argc; i++) {
						sourcePath.insert(argv[i]);
					}
					return false;
				} else {
					//dir
					//  clear source path
					sourcePath.clear();
					return false;
				}
			//################################################################################################## DISASSEMBLE
			} else if (abbrev(cmd, "disassemble", 5)) {
				const int count = getTotalInstructions();
				int ip = -1;
				int startIp = -1;
				int endIp = -1;
				Script* script = NULL;
				bool withSource = getArgFlag(argv, argc, "/m") || getArgFlag(argv, argc, "/s");
				bool printFuncName = false;
				const char* funcName = "";
				for (int i = 1; i < argc; i++) {
					if (argv[i][0] != '/') {
						char* arg = argv[i];
						arg = rawBuffer + (arg - buffer);
						//rejoinArgs(argv, argc, arg, NULL);
						argc = splitArgs(arg, ',', argv, 2);
						ip = atoi(argv[0]);
						if (ip < 0 || ip >= count) {
							printf("Invalid instruction address.\n");
							return false;
						}
						if (argc >= 2) {
							startIp = ip;
							endIp = atoi(argv[1]);
							if (argv[1][0] == '+') {
								endIp += startIp;
							}
							if (endIp <= startIp || endIp > count) {
								printf("Invalid end instruction address.\n");
								return false;
							}
							script = findScriptByIp(startIp);
							printFuncName = true;
							funcName = script->name;
						}
						break;
					}
				}
				if (startIp < 0) {
					if (ip < 0) {
						if (currentFrame == NULL) {
							printf("No frame selected.\n");
							return false;
						}
						ip = currentFrame->ip;
					}
					script = findScriptByIp(ip);
					startIp = script->instructionAddress;
					endIp = findInstruction(ip, END) + 1;
				}
				printf("Dump of assembler code from %i to %i:\n", startIp, endIp);
				int lastDisplayedLine = 0;
				const int width = snprintf(NULL, 0, "%i", endIp);
				for (int ip = startIp; ip < endIp; ip++) {
					if (script == NULL) {
						script = findScriptByIp(ip);
						funcName = script->name;
					}
					Instruction* instr = getInstruction(ip);
					if (withSource && instr->linenumber != lastDisplayedLine) {
						std::string line = getSourceLine(script->filename, instr->linenumber);
						printf("%i\t%s\n", instr->linenumber, line.c_str());
						lastDisplayedLine = instr->linenumber;
					}
					formatInstruction(script, instr, buffer);
					printf("%0*i <%s+%i>:\t%s\n", width, ip, funcName, ip - script->instructionAddress, buffer);
					if (instr->opcode == END) {
						script = NULL;
						printf("\n");
					}
				}
				printf("End of assembler dump.\n");
				return false;
			//################################################################################################## DISABLE
			} else if (streq(cmd, "disable")) {
				if (argc == 1) {
					for (Breakpoint* breakpoint : getBreakpoints()) {
						breakpoint->enabled = false;
					}
					return false;
				} else if (argc == 3 && abbrev(argv[1], "display", 4)) {
					int index = atoi(argv[2]) - 1;
					if (index < 0 || index >= (int)displays.size()) {
						printf("Invalid index.\n");
					} else {
						auto it = displays.begin();
						std::advance(it, index);
						Display* display = *it;
						display->enabled = false;
					}
					return false;
				} else {
					int index = atoi(argv[1]) - 1;
					Breakpoint* breakpoint = getBreakpointByIndex(index);
					if (breakpoint != NULL) {
						breakpoint->enabled = false;
					} else {
						printf("Breakpoint not found\n");
					}
					return false;
				}
			//################################################################################################## DISPLAY
			} else if (streq(cmd, "display")) {
				if (argc <= 1) {
					for (Display* display : displays) {
						if (display->enabled) {
							printf("%s\n", display->expression.c_str());
						}
					}
				} else {
					const char* sExpr = argv[1];
					int datatype = DT_AUTODETECT;
					if (argv[1][0] == '/') {
						const char* format = argv[1];
						sExpr = argv[2];
						if (streq(format, "/f")) {
							datatype = DT_FLOAT;
						} else if (streq(format, "/d")) {
							datatype = DT_INT;
						} else if (streq(format, "/b")) {
							datatype = DT_BOOLEAN;
						} else {
							printf("Invalid format. Valid formats are /f, /d and /b.\n");
							return false;
						}
					}
					//rejoinArgs(argv, argc, sExpr, NULL);
					sExpr = rawBuffer + (sExpr - buffer);
					Display* display = new Display(sExpr, datatype);
					displays.push_back(display);
				}
				return false;
			//################################################################################################## DOWN
			} else if (streq(cmd, "down") || streq(cmd, "down-silently")) {
				int n = argc == 2 ? atoi(argv[1]) : 1;
				moveFrame(-n, strstr(cmd, "-silently") != NULL);
				return false;
			//################################################################################################## ECHO
			} else if (streq(cmd, "echo")) {
				if (argc >= 2) {
					char* src = strchr(rawBuffer, ' ') + 1;
					char text[1024];
					char* dst = text;
					for (char c = *src; c != 0; src++, dst++, c = *src) {
						if (c == '\\') {
							c = *(++src);
							if (c == 0) {
								fgets(src, text - 1024 - src, stdin);
								src[strcspn(src, "\r\n")] = 0;
								src--;
							} else if (c == 'n') {
								*dst = '\n';
							} else if (c == 't') {
								*dst = '\t';
							} else {
								*dst = c;
							}
						} else {
							*dst = c;
						}
					}
					*dst = 0;
					printf("%s", text);
				}
				return false;
			//################################################################################################## ENABLE
			} else if (streq(cmd, "enable")) {
				if (argc == 1) {
					for (Breakpoint* breakpoint : getBreakpoints()) {
						breakpoint->enabled = true;
						breakpoint->disabledByTrigger = false;
					}
					return false;
				} else if (argc == 3 && abbrev(argv[1], "display", 4)) {
					int index = atoi(argv[2]) - 1;
					if (index < 0 || index >= (int)displays.size()) {
						printf("Invalid index.\n");
					} else {
						auto it = displays.begin();
						std::advance(it, index);
						Display* display = *it;
						display->enabled = true;
					}
					return false;
				} else {
					bool once = getArgFlag(argv, argc, "once");
					bool deleteOnHit = getArgFlag(argv, argc, "del");
					int index = atoi(argv[argc - 1]) - 1;
					Breakpoint* breakpoint = getBreakpointByIndex(index);
					if (breakpoint != NULL) {
						breakpoint->enable();
						if (once) {
							breakpoint->targetHitCount = 1;
						}
						if (deleteOnHit) {
							breakpoint->deleteOnHit = true;
						}
					} else {
						printf("Breakpoint not found\n");
					}
					return false;
				}
			//################################################################################################## EVAL
			} else if (streq(cmd, "eval")) {
				if (argc >= 2) {
					char* sArgs = strchr(rawBuffer, ' ') + 1;
					argc = splitArgs(sArgs, ',', argv, MAX_ARGS);
					char* format = argv[0];
					char line[1024];
					int len = usprintf(line, argv[0], argc - 1, argv + 1);
					if (len > 0) {
						commandQueue.push(line);
					}
					return false;
				}
			//################################################################################################## FINISH
			} else if (streq(cmd, "finish")) {
				if (currentFrame == NULL) {
					printf("No frame selected.\n");
					return false;
				}
				const int count = getTotalInstructions();
				int ip = findInstruction(currentFrame->ip, END);
				if (ip < 0) {
					printf("Cannot find end of script\n");
					return false;
				}
				breakFromAddress = ip;
				steppingThread = getThread(currentFrame);
				breakAfterLines = 1;
				stepInMaxDepth = 9999;
				return true;
			//################################################################################################## FRAME
			} else if (abbrev(cmd, "frame", 1) || streq(cmd, "select-frame")) {
				if (currentFrame == NULL) {
					printf("No frame selected.\n");
					return false;
				}
				auto backtrace = getBacktrace(currentFrame);
				int frameIndex = backtrace.size() - 1 - getFrameDepth(currentFrame);
				if (argc < 2) {
					printFrame(currentFrame, frameIndex);
				} else {
					int frameIndex = atoi(argv[1]);
					if (frameIndex < 0 || frameIndex >= (int)backtrace.size()) {
						printf("Invalid frame\n");
					} else {
						currentFrame = backtrace[frameIndex];
						if (!streq(cmd, "select-frame")) {	//Silent version
							printFrame(currentFrame, frameIndex);
						}
					}
				}
				return false;
			//################################################################################################## IGNORE
			} else if (streq(cmd, "ignore")) {
				if (argc >= 3) {
					int index = atoi(argv[1]) - 1;
					int count = atoi(argv[2]);
					Breakpoint* breakpoint = getBreakpointByIndex(index);
					if (breakpoint != NULL) {
						breakpoint->enable();
						breakpoint->targetHitCount = count + 1;
					} else {
						printf("Breakpoint not found\n");
					}
					return false;
				}
			//################################################################################################## INFO
			} else if (streq(cmd, "info")) {
				if (argc >= 2) {
					const char* arg = argv[1];
					//################################################################################################## INFO ADDRESS
					if (streq(arg, "address")) {
						if (argc >= 3) {
							//info address s
							//  show where symbol s is stored
							arg = argv[2];
							if (currentFrame != NULL) {
								Script* script = getTaskScript(currentFrame);
								int varId = getLocalVarId(script, arg, 0);
								if (varId >= 0) {
									printf("Local %i\n", varId);
								}
							}
							int varId = getGlobalVarId(arg, 0);
							if (varId >= 0) {
								printf("Global %i\n", varId);
							} else {
								printf("Symbol not found\n");
							}
							return false;
						}
					//################################################################################################## INFO ARGS
					} else if (streq(arg, "args")) {
						//info args
						//  arguments of selected frame
						if (currentFrame == NULL) {
							printf("No frame selected.");
							return false;
						}
						Script* script = getTaskScript(currentFrame);
						for (DWORD i = 0; i < script->parameterCount; i++) {
							Var* var = &currentFrame->localVars.pFirst[i];
							printf("%i: %s = %f\n", i, var->name, var->floatVal);
						}
						return false;
					//################################################################################################## INFO BREAKPOINTS
					} else if (abbrev(arg, "breakpoints", 5)) {
						//info breakpoints
						//  show defined breakpoints
						int index = 1;
						for (Breakpoint* breakpoint : getBreakpoints()) {
							const char* enabled = breakpoint->enabled ? "enabled" : "disabled";
							printf("%5i breakpoint %-8s %8i %s:%i\n", index++, enabled, breakpoint->ip,
									breakpoint->filename.c_str(), breakpoint->lineno);
						}
						for (Watch* watch : getWatches()) {
							if (watch->task == NULL) {
								printf("%5i watchpoint %-8s %8i %s\n", index++, "enabled", 0, watch->expression->str.c_str());
							} else {
								printf("%5i watchpoint %-8s %8i %s (Task %i)\n", index++, "enabled", 0,
										watch->expression->str.c_str(), watch->task->taskNumber);
							}
						}
						for (int i = 0; i < NATIVE_COUNT; i++) {
							if (catchSysCalls[i]) {
								printf("%5i catchpoint %-8s %8i %s\n", index++, "enabled", 0, NativeFunctions[i]);
							}
						}
						return false;
					//################################################################################################## INFO DISPLAY
					} else if (streq(arg, "display")) {
						int i = 1;
						for (Display* display : displays) {
							const char* enabled = display->enabled ? "" : " (disabled)";
							printf("%3i: %s%s\n", i++, display->expression.c_str(), enabled);
						}
						return false;
					//################################################################################################## INFO LOCALS
					} else if (streq(arg, "locals")) {
						//info locals
						if (currentFrame == NULL) {
							printf("No frame selected.");
							return false;
						}
						const int count = getLocalVarsCount(currentFrame);
						for (int i = 0; i < count; i++) {
							Var* var = &currentFrame->localVars.pFirst[i];
							if (streq(var->name, "LHVMA")) {
								printf(", %f", var->floatVal);
							} else {
								if (i > 0) printf("\n");
								if (i < count - 1 && streq(currentFrame->localVars.pFirst[i + 1].name, "LHVMA")) {
									printf("%s[]: %f", var->name, var->floatVal);
								} else {
									printf("%s: %f", var->name, var->floatVal);
								}
							}
						}
						printf("\n");
						return false;
					//################################################################################################## INFO REG
					} else if (abbrev(arg, "reg", 1)) {
						//info reg [rn]
						//  register values [for regs rn] in selected frame
						if (currentFrame == NULL) {
							printf("No frame selected.");
							return false;
						}
						#define PR_REG(REG, EXPR) if (argc <= 2 || inArray(REG, argv+2, argc-2)) printf("%-3s %9i\n", REG, EXPR);
						PR_REG("ip", currentFrame->ip);
						PR_REG("sc", currentFrame->stack.count);
						PR_REG("gc", currentFrame->globalsCount);
						PR_REG("lc", getLocalVarsCount(currentFrame));
						PR_REG("ieh", currentFrame->inExceptionHandler);
						PR_REG("ceh", currentFrame->currentExceptionHandlerIndex);
						PR_REG("pip", currentFrame->prevIp);
						PR_REG("tid", currentFrame->taskNumber);
						PR_REG("sid", currentFrame->scriptID);
						PR_REG("wid", currentFrame->waitingTask);
						PR_REG("typ", currentFrame->type);
						PR_REG("slp", currentFrame->sleeping);
						PR_REG("tks", currentFrame->ticks);
						#undef PR_REG
						return false;
					//################################################################################################## INFO SOURCE
					} else if (streq(arg, "source")) {
						//info source
						//  show name of current source file
						if (currentFrame != NULL) {
							printf("%s\n", currentFrame->filename);
						} else {
							printf("No frame selected.\n");
						}
						return false;
					//################################################################################################## INFO SOURCES
					} else if (streq(arg, "sources")) {
						//info sources
						//  list all source files in use
						ScriptEntry* scriptEntry = *ScriptLibraryR.pScriptList;
						while (scriptEntry != NULL) {
							Script* script = scriptEntry->script;
							printf("%s\n", script->filename);
							scriptEntry = scriptEntry->next;
						}
						return false;
					//################################################################################################## INFO THREADS
					} else if (streq(arg, "threads")) {
						//info threads
						//  list all threads
						char targetId[255], sFrame[255];
						Task* currentThread = currentFrame != NULL ? getThread(currentFrame) : NULL;
						int id = 0;
						std::vector<Task*> threads = getThreads();
						printf("%-2s%-5s%-50s%s\n", "", "Id", "Target Id", "Frame");
						for (Task* thread : threads) {
							++id;
							bool show = argc <= 2 || inArray(id, &argv[2], argc - 2);
							if (show && thread != NULL) {
								Task* tFrame = getFrame(thread);
								char args[512];
								formatTaskParameters(tFrame, args);
								Instruction* instruction = getCurrentInstruction(tFrame);
								const char* current = thread == currentThread ? "*" : " ";
								sprintf(targetId, "Thread %i \"%s\"", thread->taskNumber, thread->name);
								sprintf(sFrame, "%s (%s) at %s:%i", tFrame->name, args, tFrame->filename, instruction->linenumber);
								printf("%-2s%-5i%-50s%s\n", current, id, targetId, sFrame);
							}
						}
						return false;
					}
				}
			//################################################################################################## JUMP
			} else if (abbrev(cmd, "jump", 1)) {
				if (argc >= 2) {
					if (currentFrame == NULL) {
						printf("No frame selected.");
						return false;
					}
					char* arg = argv[1];
					int ip = -1;
					const char* file = currentFrame->filename;
					int line = -1;
					if (arg[0] == '*') {
						ip = atoi(arg + 1);
						if (ip < 0 || ip >= getTotalInstructions()) {
							printf("Invalid instruction address: %i\n", ip);
							return false;
						}
					} else {
						line = atoi(arg);
						ip = findInstructionIndex(file, line);
						if (ip == -1) {
							printf("Invalid jump line %i in file %s\n", line, file);
							return false;
						} else if (ip == -2) {
							printf("File %s not found\n", file);
							return false;
						}
					}
					Script* script = findScriptByIp(ip);
					if (script->id != currentFrame->scriptID) {
						printf("Cannot jump to a location belonging to another script\n");
					} else {
						bool doJump = true;
						if (currentFrame->stack.count > 0) {
							prompt("The stack is not empty, are you sure to jump? (y or n) ");
							doJump = streq(buffer, "y");
						}
						if (doJump) {
							jump(currentFrame, ip);
							printCurrentLine(currentFrame);
						}
					}
					return false;
				}
			//################################################################################################## KILL
			} else if (streq(cmd, "kill")) {
				//kill running program
				ExitProcess(1);
				return false;
			//################################################################################################## LIST
			} else if (streq(cmd, "list")) {
				const char* file = lastPrintedFile;
				int first = 1;
				int last = 10;
				if (argc == 1) {
					if (currentFrame != NULL) {
						file = currentFrame->filename;
						if (lastPrintedLine > 0) {
							first = lastPrintedLine + 1;
							last = first + 9;
						} else {
							Instruction* instr = getCurrentInstruction(currentFrame);
							first = instr->linenumber - 6;
							last = first + 9;
						}
					} else {
						printf("Source file not set\n");
						return false;
					}
				} else if (argc >= 2) {
					char* arg = argv[1];
					if (streq(arg, "-")) {
						last = firstPrintedLine - 1;
						first = last - 9;
					} else if (arg[0] == '+') {
						first = lastPrintedLine + 1;
						last = lastPrintedLine + atoi(arg);
					} else if (arg[0] == '-') {
						last = firstPrintedLine - 1;
						first = firstPrintedLine + atoi(arg);
					} else if (arg[0] == '*') {
						int ip = atoi(arg + 1);
						file = findFilenameByIp(ip);
						Instruction* instruction = getInstruction(ip);
						first = instruction->linenumber;
						last = first;
					} else if (strchr(arg, ',')) {
						argc = splitArgs(arg, ',', argv, 2);
						first = atoi(argv[0]);
						last = atoi(argv[1]);
						if (first > last) {
							printf("First line must be not greater than last\n");
							return false;
						}
					} else {
						argc = splitArgs(arg, ':', argv, 2);
						if (argc >= 2) {
							file = argv[0];
						}
						first = atoi(argv[argc - 1]);
						last = first;
					}
				}
				if (file != NULL) {
					std::vector<std::string> source = getSource(file);
					if (source.empty()) {
						printf("File %s not found\n", file);
					} else {
						first = max(1, first);
						last = min(last, (int)source.size());
						for (int i = first; i <= last; i++) {
							printf("%i: %s\n", i, source[i - 1].c_str());
						}
						firstPrintedLine = first;
						lastPrintedLine = last;
						strcpy(lastPrintedFile, file);
					}
				} else {
					printf("File not set\n");
				}
				return false;
			//################################################################################################## NEXT
			} else if (abbrev(cmd, "next", 1)) {
				if (currentFrame != NULL) {
					breakAfterLines = argc >= 2 ? atoi(argv[1]) : 1;
					steppingThread = getThread(currentFrame);
					stepInMaxDepth = getFrameDepth(currentFrame);
					return true;
				} else {
					printf("Execution must be paused to step\n");
					return false;
				}
			//################################################################################################## NEXTI
			} else if (streq(cmd, "ni") || streq(cmd, "nexti")) {
				if (currentFrame != NULL) {
					breakAfterInstructions = argc >= 2 ? atoi(argv[1]) : 1;
					steppingThread = getThread(currentFrame);
					stepInMaxDepth = getFrameDepth(currentFrame);
					return true;
				} else {
					printf("Execution must be paused to step\n");
					return false;
				}
			//################################################################################################## OUTPUT
			} else if (streq(cmd, "output")) {
				if (argc >= 2) {
					uprint(rawBuffer, "", "");
					return false;
				}
			//################################################################################################## PRINT
			} else if (abbrev(cmd, "print", 1)) {
				if (argc >= 2) {
					uprint(rawBuffer, "$1 = ", "\n");
					return false;
				}
			//################################################################################################## PRINTF
			} else if (streq(cmd, "printf")) {
				if (argc >= 2) {
					char* sArgs = strchr(rawBuffer, ' ') + 1;
					argc = splitArgs(sArgs, ',', argv, MAX_ARGS);
					char* format = argv[0];
					char line[1024];
					int len = usprintf(line, argv[0], argc - 1, argv + 1);
					if (len >= 0) {
						printf("%s", line);
					}
					return false;
				}
			//################################################################################################## QUIT
			} else if (abbrev(cmd, "quit", 1)) {
				//quit
				ExitProcess(1);
				return false;
			//################################################################################################## RETURN
			} else if (abbrev(cmd, "return", 3)) {
				if (currentFrame == NULL) {
					printf("No frame selected.");
					return false;
				}
				if (currentFrame != getInnermostFrame(currentFrame)) {
					printf("Can only return when current frame is the innermost.");
					return false;
				}
				prompt("Make %s return now? (y or n) ", currentFrame->name);
				if (streq(buffer, "y")) {
					int ip = findInstruction(currentFrame->ip, END);
					if (ip < 0) {
						printf("Cannot find end of script\n");
					} else {
						currentFrame->ip = ip;
						printCurrentInstruction(currentFrame);
					}
				}
				return false;
			//################################################################################################## RUN
			} else if (abbrev(cmd, "run", 1)) {
				if (argc == 1) {
					printf("Continuing.\n");
					return true;
				} else if (argc >= 2) {
					char* scriptName = argv[1];
					Script* script = getScriptByName(scriptName);
					if (script == NULL) {
						printf("Script %s not found\n", scriptName);
						return false;
					}
					if (argc >= 3) {
						char* sArgs = rawBuffer + (argv[2] - buffer);
						argc = splitArgs(sArgs, ',', argv, MAX_ARGS);
					} else {
						argc = 0;
					}
					if (argc != script->parameterCount) {
						printf("Script %s expects %i parameters\n", scriptName, script->parameterCount);
						return false;
					}
					//Evaluate parameters
					FLOAT params[MAX_ARGS];
					for (int i = 0; i < argc; i++) {
						int datatype = DT_FLOAT;
						Var* param = evalString(currentFrame, argv[i], datatype);
						if (param == NULL) {
							printf("Failed to evaluate parameter %i.\n", i);
							return false;
						}
						params[i] = param->floatVal;
					}
					//Push parameters on the stack
					for (int i = 0; i < argc; i++) {
						ScriptLibraryR.PUSH(params[i], 2);
					}
					//Start the script
					int taskNumber = ScriptLibraryR.StartScript(NULL, scriptName, 0xFFFFFFFF);
					if (taskNumber != 0) {
						breakAfterLines = 1;
						steppingThread = getTaskById(taskNumber);
						return true;
					} else {
						printf("Failed to start script %s\n", scriptName);
						return false;
					}
				}
			//################################################################################################## SET
			} else if (streq(cmd, "set")) {
				if (argc >= 2) {
					char* type = argv[1];
					if (streq(type, "print")) {
						if (argc == 4) {
							char* prop = argv[2];
							char* sVal = argv[3];
							if (streq(prop, "elements")) {
								maxPrintElements = atoi(sVal);
								maxPrintElements = MAX(1, maxPrintElements);
							} else {
								printf("Invalid property.\n");
							}
							return false;
						}
					} else {
						char* sExpr = argv[1];
						if (streq(type, "var") || streq(type, "variable")) {
							if (argc < 3) {
								printf("Expected expression\n.");
								return false;
							}
							sExpr = argv[2];
						}
						sExpr = rawBuffer + (sExpr - buffer);
						//rejoinArgs(argv, argc, sExpr, NULL);
						if (strchr(sExpr, '=') != NULL) {
							splitArgs(sExpr, '=', argv, 2);
							char* name = argv[0];
							char* sValue = argv[1];
							if (streq(name, "$ip")) {
								currentFrame->ip = atoi(sValue);
								printCurrentInstruction(currentFrame);
							} else if (streq(name, "$sc")) {
								currentFrame->stack.count = atoi(sValue);
							} else if (streq(name, "$tks")) {
								currentFrame->ticks = atoi(sValue);
							} else {
								int varId;
								if (strncmp(name, "{int}", 5) == 0) {
									varId = atoi(name + 5);
									Var* var = getVarById(currentFrame, varId);
									if (var == NULL) {
										printf("Invalid variable ID.\n");
										return false;
									}
								} else {
									Script* script = getTaskScript(currentFrame);
									varId = getVarId(script, name);
									if (varId < 0 && name[0] == '_' && currentFrame != NULL) {
										int gVarId = ScriptLibraryR.createVar(name, 2, NULL, TRUE);
										printf("Global variable '%s' defined with ID %i\n", name, gVarId);
									}
								}
								if (varId >= 0) {
									Var* var = getVarById(currentFrame, varId);
									if (streq(sValue, "true")) {
										var->floatVal = 1.0;
									} else if (streq(sValue, "false")) {
										var->floatVal = 0.0;
									} else {
										int datatype = DT_FLOAT;
										Var* res = evalString(currentFrame, sValue, datatype);
										if (res != NULL) {
											var->floatVal = res->floatVal;
										}
									}
								} else {
									Script* script = getTaskScript(currentFrame);
									std::string code = "\t" + std::string(name) + " = " + std::string(sValue) + "\n0";
									Expression* expr = getCompiledExpression(script, code, DT_FLOAT);
									if (expr != NULL) {
										evalExpression(currentFrame, expr);
									}
								}
							}
						} else {
							printf("Expected =\n");
						}
					}
					return false;
				}
			//################################################################################################## SHOW
			} else if (streq(cmd, "show")) {
				if (argc >= 2) {
					char* arg = argv[1];
					if (streq(arg, "dir")) {
						//show dir
						//  show current source path
						if (sourcePath.empty()) {
							printf("<empty>\n");
						} else {
							for (std::string dir : sourcePath) {
								printf("%s\n", dir.c_str());
							}
						}
						return false;
					}
				}
			//################################################################################################## SOURCE
			} else if (streq(cmd, "source")) {
				if (argc >= 2) {
					char* filename = argv[1];
					filename = rawBuffer + (filename - buffer);
					//rejoinArgs(argv, argc, filename, NULL);
					std::string absFilename = searchPaths(sourcePath, filename);
					if (absFilename == "") {
						printf("File not found.\n");
					} else {
						FILE* file = fopen(absFilename.c_str(), "rt");
						if (file == NULL) {
							printf("Failed to open file '%s'\n", absFilename.c_str());
						} else {
							while (fgets(buffer, BUFFER_SIZE, file)) {
								buffer[strcspn(buffer, "\r\n")] = 0;
								commandQueue.push(buffer);
							}
							fclose(file);
						}
					}
					return false;
				}
			//################################################################################################## STEP
			} else if (abbrev(cmd, "step", 1)) {
				//step [count]
				//  execute until another line reached; repeat count times if specified
				if (currentFrame != NULL) {
					breakAfterLines = argc >= 2 ? atoi(argv[1]) : 1;
					steppingThread = getThread(currentFrame);
					stepInMaxDepth = 9999;
					return true;
				} else {
					printf("Execution must be paused to step\n");
					return false;
				}
			//################################################################################################## STEPI
			} else if (streq(cmd, "si") || streq(cmd, "stepi")) {
				//stepi
				//  step by machine instructions rather than source lines
				if (currentFrame != NULL) {
					breakAfterInstructions = argc >= 2 ? atoi(argv[1]) : 1;
					steppingThread = getThread(currentFrame);
					stepInMaxDepth = 9999;
					return true;
				} else {
					printf("Execution must be paused to step\n");
					return false;
				}
			//################################################################################################## TBREAK
			//} else if (streq(cmd, "tbreak")) {	//merged with break
			//################################################################################################## THREAD
			} else if (streq(cmd, "thread")) {
				if (argc == 2) {
					int threadId = atoi(argv[1]);
					auto threads = getThreads();
					if (threadId < 1 || threadId > (int)threads.size()) {
						printf("Invalid thread ID.\n");
						return false;
					}
					Task* thread = threads[threadId - 1];
					if (thread == getThread(currentFrame)) {
						printf("Thread already selected.\n");
						return false;
					}
					allowedThreadId = thread->taskNumber;
					steppingThread = thread;
					breakFromAddress = 0;
					return true;
				}
			//################################################################################################## UNDISPLAY
			} else if (streq(cmd, "undisplay")) {
				if (argc == 2) {
					int index = atoi(argv[1]) - 1;
					if (index < 0 || index >= (int)displays.size()) {
						printf("Invalid index.\n");
					} else {
						auto it = displays.begin();
						std::advance(it, index);
						Display* display = *it;
						displays.erase(it);
						delete display;
					}
					return false;
				}
			//################################################################################################## UNTIL
			} else if (abbrev(cmd, "until", 1)) {
				if (currentFrame == NULL) {
					printf("No frame selected.");
					return false;
				}
				if (currentFrame != getInnermostFrame(currentFrame)) {
					printf("Please select the innermost frame.");
					return false;
				}
				int ip = -1;
				const char* file = currentFrame->filename;
				if (argc >= 2) {
					const char* arg = argv[1];
					if (arg[0] == '*') {
						ip = atoi(arg + 1);
						if (ip < 0 || ip >= getTotalInstructions()) {
							printf("Invalid instruction address: %i\n", ip);
							return false;
						}
					} else {
						int line = atoi(arg);
						ip = findInstructionIndex(file, line);
						if (ip == -1) {
							printf("Invalid line %i in file %s\n", line, file);
							return false;
						} else if (ip == -2) {
							printf("File %s not found\n", file);
							return false;
						}
					}
					breakFromAddress = ip;
					breakAfterLines = 0;
					steppingThread = getThread(currentFrame);
					stepInMaxDepth = getFrameDepth(currentFrame);
					return true;
				} else {
					const int count = getTotalInstructions();
					ip = currentFrame->ip;
					Instruction* instr = getInstruction(ip);
					const DWORD currentLine = instr->linenumber;
					for (ip++; ip < count; ip++) {
						instr = getInstruction(ip);
						if (instr->linenumber > currentLine) {
							breakFromAddress = ip;
							breakAfterLines = 0;
							steppingThread = getThread(currentFrame);
							stepInMaxDepth = getFrameDepth(currentFrame);
							return true;
						} else if (instr->opcode == END) {
							break;
						}
					}
					printf("No more lines in current script.\n");
					return false;
				}
			//################################################################################################## UP
			} else if (streq(cmd, "up")) {
				int n = argc == 2 ? atoi(argv[1]) : 1;
				moveFrame(n, strstr(cmd, "-silently") != NULL);
				return false;
			//################################################################################################## WATCH
			} else if (streq(cmd, "watch")) {
				if (argc >= 2) {
					const char* sExpr = argv[1];
					sExpr = rawBuffer + (sExpr - buffer);
					//rejoinArgs(argv, argc, sExpr, NULL);
					addWatch(currentFrame, sExpr);
					return false;
				}
			//################################################################################################## WHATIS
			} else if (streq(cmd, "whatis")) {
				if (argc >= 2) {
					const char* sExpr = argv[1];
					sExpr = rawBuffer + (sExpr - buffer);
					//rejoinArgs(argv, argc, sExpr, NULL);
					Script* script = getTaskScript(currentFrame);
					Expression* expr = getCompiledExpression(script, sExpr, DT_AUTODETECT);
					if (expr != NULL) {
						printf("%s\n", datatype_names[expr->datatype]);
					}
					return false;
				}
			//################################################################################################## X
			} else if (streq(cmd, "x")) {
				if (argc >= 2) {
					int count = 1;
					const char* sExpr = argv[1];
					if (argv[1][0] == '/') {
						count = atoi(argv[1] + 1);
						if (argc < 3) {
							printf("Expected expression\n");
							return false;
						}
						sExpr = argv[2];
					}
					sExpr = rawBuffer + (sExpr - buffer);
					//rejoinArgs(argv, argc, sExpr, NULL);
					if (streq(sExpr, "$sp")) {	//Special case to see the stack
						if (currentFrame == NULL) {
							printf("No frame selected.");
							return false;
						}
						const int first = max(0, (int)currentFrame->stack.count - count);
						for (int i = (int)currentFrame->stack.count - 1; i >= first; i--) {
							DWORD type = currentFrame->stack.types[i];
							int id; Var* var; int index;
							switch (type) {
								case DT_FLOAT:
								case DT_COORDS:
									printf("%2i: %c %f\n", i, datatype_chars[type], currentFrame->stack.floatVals[i]);
									break;
								case DT_VAR:
									id = (int)currentFrame->stack.floatVals[i];
									var = getBaseAndIndex(currentFrame, id, &index);
									if (var != NULL) {
										if (varIsArray(currentFrame, var)) {
											printf("%2i: v %i (&%s[%i])\n", i, id, var->name, index);
										} else {
											printf("%2i: v %i (&%s)\n", i, id, var->name);
										}
									} else {
										printf("%2i: v %i (invalid var id)\n", i, id);
									}
									break;
								default:
									printf("%2i: %c %i\n", i, datatype_chars[type], currentFrame->stack.intVals[i]);
							}
						}
					} else {
						int varId = atoi(sExpr);
						if (varId == 0 && !streq(sExpr, "0")) {
							Script* script = getTaskScript(currentFrame);
							varId = getVarId(script, sExpr);
							if (varId < 0) {
								printf("Variable not found\n");
								return false;
							}
						} else {
							if (varId < 0 || (currentFrame == NULL && varId >= getGlobalVarsCount()) ||
									(currentFrame != NULL && varId > (int)currentFrame->globalsCount + getLocalVarsCount(currentFrame))) {
								printf("Invalid variable id\n");
								return false;
							}
						}
						int index;
						Var* var = getBaseAndIndex(currentFrame, varId, &index);
						if (var == NULL) {
							printf("Invalid variable ID.\n");
							return false;
						}
						bool glb = varIsGlobal(var);
						if (glb) {
							printf("-- printing global variables --\n");
						} else {
							printf("-- printing local variables --\n");
						}
						bool arr = varIsArray(currentFrame, var);
						const char* prefix = glb || currentFrame == NULL ? "global" : currentFrame->name;
						const char* baseName = var->name;
						var += index;
						for (int i = 0; i < count; i++, varId++, var++) {
							if (currentFrame == NULL) {
								if (var >= ScriptLibraryR.globalVars->pEnd) {
									printf("-- no more global vars --\n");
									break;
								}
							} else {
								if (glb) {
									if (varId > (int)currentFrame->globalsCount) {
										printf("-- subsequent address mapped to local vars --\n");
										if (getLocalVarsCount(currentFrame) == 0) {
											printf("-- no local vars --\n");
											break;
										}
										var = currentFrame->localVars.pFirst;
										glb = false;
										arr = varIsArray(currentFrame, var);
										prefix = currentFrame->name;
									}
								} else if (var >= currentFrame->localVars.pEnd) {
									printf("-- no more local vars --\n");
									break;
								}
							}
							if (streq(var->name, "LHVMA")) {
								index++;
							} else {
								baseName = var->name;
								arr = varIsArray(currentFrame, var);
								index = 0;
							}
							if (arr) {
								printf("%5i %s.%s[%i]:\t%f\n", varId, prefix, baseName, index, var->floatVal);
							} else {
								printf("%5i %s.%s:\t%f\n", varId, prefix, baseName, var->floatVal);
							}
						}
					}
					return false;
				}
			//################################################################################################## HELP
			} else if (streq(cmd, "help")) {
				if (argc < 2) {
					//TODO
					printf("Help not available\n");
					return false;
				} else {
					char* topic = argv[1];
					//TODO
					printf("Help for \"%s\" not available\n", topic);
					return false;
				}
			//################################################################################################## <USER_COMMAND>
			} else if (userCommands.contains(cmd)) {
				auto& ucmd = userCommands[cmd];
				for (auto line : ucmd.commands) {
					for (int i = 1; i < argc; i++) {
						line = strReplace(line, "$arg"+std::to_string(i - 1), argv[i]);
					}
					commandQueue.push(line);
				}
				return false;
			}
			printf("Invalid command. Enter \"help\" to get a list of available commands.\n");
			return false;
		}
};

char Gdb::buffer[BUFFER_SIZE];
char* Gdb::argv[MAX_ARGS];

std::queue<std::string> Gdb::commandQueue = std::queue<std::string>();

Breakpoint* Gdb::lastHitBreakpoint;

char Gdb::lastPrintedFile[256];
int Gdb::firstPrintedLine = 0;
int Gdb::lastPrintedLine = 0;

Task* Gdb::currentFrame = NULL;
int Gdb::compiledThreadId = 0;
int Gdb::resumeThreadId = 0;

std::list<Display*> Gdb::displays = std::list<Display*>();

std::map<std::string, UserCommand> Gdb::userCommands = std::map<std::string, UserCommand>();

int Gdb::maxPrintElements = 200;
