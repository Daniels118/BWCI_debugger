#pragma once

#define DEBUGGER_GDB

#include "ScriptLibraryR.h"
#include "debug.h"
#include "assembler.h"
#include "utils.h"

#include <iostream>
#include <queue>
#include <regex>

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

		static std::list<std::string> commandQueue;

		static Breakpoint* lastHitBreakpoint;

		static char lastPrintedFile[256];
		static int firstPrintedLine;
		static int lastPrintedLine;
		static Task* lastPrintedLineTask;
		static int lastPrintedLineIp;

		static Task* currentFrame;
		static int compiledThreadId;
		static int resumeThreadId;
		static bool runningCompileCommand;

		static std::list<Display*> displays;

		static std::map<std::string, UserCommand> userCommands;

		static int maxPrintElements;
		static bool echo_on;

		static const int BLOCK = 1;
		static const int LOOP = 2;
		static std::vector<int> blocks;
		static int inScript;

		static bool captureKilledThreads;
		static std::list<TaskInfo> killedThreads;

		static int shell_exitcode_id;

		static HWND gameWindow;
		static HWND consoleWindow;
		static HHOOK keyHook;

	public:
		Gdb() {
			#ifdef CHL_ASSEMBLER
				assembler_init();
			#endif
			char* cmd = GetCommandLineA();
			strcpy(buffer, cmd);
			int argc = splitArgs(buffer, ' ', argv, MAX_ARGS);
			char* script = getArgVal(argv, argc, "/gdb:script");
			if (script != NULL) {
				commandQueue.push_front("source " + std::string(script));
			}
		}

		void init() {
			consoleWindow = GetConsoleWindow();
			if (consoleWindow == NULL) {
				AllocConsole();
				consoleWindow = GetConsoleWindow();
				FILE* t;
				t = freopen("CONOUT$", "w", stdout);
				t = freopen("CONIN$", "r", stdin);
			}
			if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
				printf("ERROR: cannot set control handler\n");
			}
			//
			gameWindow = findProcessWindowExcluding(NULL, consoleWindow);
			keyHook = SetWindowsHookExW(WH_KEYBOARD, keyHookHandler, NULL, GetCurrentThreadId());
			if (keyHook == NULL) {
				printf("Failed to install keyboard hook.");
			}
			//
			printf("\n");
			printf("Debugging using gdb interface.\n");
			printf("Press CTRL+C to break the execution and get a prompt. For help, type \"help\".\n");
		}

		void term() {
			if (keyHook != NULL) {
				UnhookWindowsHookEx(keyHook);
			}
		}

		void start() {
			shell_exitcode_id = getOrDeclareGlobalVar("_shell_exitcode", 1, 0.0);
		}

		void threadStarted(Task* thread) {
			if (!runningCompileCommand) {
				printf("New Thread %i \"%s\"\n", thread->taskNumber, thread->name);
			}
		}

		void threadResumed(Task* thread) {
			Task* frame = getInnermostFrame(thread);
			Instruction* instr = getCurrentInstruction(frame);
			printf("Thread %i \"%s\" resumed, currently in \"%s\" at %s:%i\n", thread->taskNumber, thread->name, frame->name, frame->filename, instr->linenumber);
		}

		void threadEnded(void* pThread, TaskInfo* info) {
			if (pThread == catchThread) {
				catchThread = NULL;
			}
			if (info->id == compiledThreadId) {
				if (deleteScriptByName("_gdb_expr_")) {
					unsetSource("__debugger_compile");
				}
				allowedThreadId = resumeThreadId;	//Resume from previous thread (if any)
				if (resumeThreadId > 0) {			//if there was a previous thread
					pause = true;					//  stop when previous thread resumes
				} else {							//else prompt for new commands
					compiledThreadId = 0;
					runningCompileCommand = false;
					readAndExecuteCommand(NULL);
				}
			} else {
				printf("Thread %i \"%s\" ended\n", info->id, info->name.c_str());
				if (captureKilledThreads) {
					killedThreads.push_back(*info);
				}
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
			commandQueue.insert(commandQueue.begin(), breakpoint->commands.begin(), breakpoint->commands.end());
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
			if (task != lastPrintedLineTask || task->ip != lastPrintedLineIp) {
				printDisplays(task);
				printCurrentInstruction(task);
				lastPrintedLineTask = task;
				lastPrintedLineIp = task->ip;
			}
			readAndExecuteCommand(task);
		}

		void onPauseBeforeLine(Task* task) {
			checkTempScriptEnded();
			if (task != lastPrintedLineTask || task->ip != lastPrintedLineIp) {
				printDisplays(task);
				printCurrentLine(task);
				lastPrintedLineTask = task;
				lastPrintedLineIp = task->ip;
			}
			readAndExecuteCommand(task);
		}

		void onException(Task* task, bool exception, std::list<Watch*> watches) {
			for (Watch* watch : watches) {
				printf("Old value = %f\n", watch->oldValue);
				printf("New value = %f\n", watch->newValue);
				printf("Watchpoint: %s\n", watch->getExpression()->str.c_str());
			}
			if (exception) {
				printf("Exception in Thread %i\n", catchThread->taskNumber);
			}
			printDisplays(task);
			printCurrentLine(task);
			readAndExecuteCommand(task);
		}

		void onMessage(DWORD severity, const char* format, ...) {
			if (severity != 0 && !runningCompileCommand) {
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
						commandQueue.clear();
						printf("\nScript execution interrupted.\n");
					}
					printf("\nPaused.\n");
					if (ScriptLibraryR.pTaskList->count > 0 && !gamePaused) {
						pause = true;
					} else {
						readAndExecuteCommand(NULL);
					}
					return TRUE;
				default:
					return FALSE;
			}
		}

		static LRESULT CALLBACK keyHookHandler(int code, WPARAM wParam, LPARAM lParam) {
			if (code >= 0) {
				if (wParam == 0x43 && lParam & 0x80000000 && GetKeyState(VK_CONTROL) & 0x8000) {	//CTRL+C (on keyup)
					printf("\nPaused.\n");
					if (ScriptLibraryR.pTaskList->count > 0 && !gamePaused) {
						pause = true;
					} else {
						readAndExecuteCommand(NULL);
					}
				}
			}
			return CallNextHookEx(NULL, code, wParam, lParam);
		}

		static void activateConsole() {
			if (GetForegroundWindow() != consoleWindow) {
				SetForegroundWindow(consoleWindow);
				SetActiveWindow(consoleWindow);
			}
		}

		static void activateGameWindow() {
			if (GetForegroundWindow() != gameWindow) {
				SetForegroundWindow(gameWindow);
				SetActiveWindow(gameWindow);
			}
		}

		static void checkTempScriptEnded() {
			if (runningCompileCommand && !ScriptLibraryR.taskExists(compiledThreadId)) {
				resumeThreadId = 0;
				allowedThreadId = 0;
				compiledThreadId = 0;
				runningCompileCommand = false;
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
								if (val->type == DT_OBJECT) {
									printf("%i: %s = %u (object)\n", i, display->expression.c_str(), val->uintVal);
								} else {
									printf("%i: %s = %f\n", i, display->expression.c_str(), val->floatVal);
								}
							} else if (expr->datatype == DT_INT) {
								printf("%i: %s = %i\n", i, display->expression.c_str(), (int)val->floatVal);
							} else if (expr->datatype == DT_BOOLEAN) {
								printf("%i: %s = %s\n", i, display->expression.c_str(), val->floatVal != 0.0f ? "true" : "false");
							} else if (expr->datatype == DT_COORDS) {
								printf("%i: %s = [%f, %f, %f]\n", i, display->expression.c_str(),
										val[0].floatVal, val[1].floatVal, val[2].floatVal);
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
			if (runningCompileCommand && task->taskNumber != compiledThreadId) {
				return;
			}
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
			if (echo_on || commandQueue.empty()) {
				va_list args;
				va_start(args, format);
				vprintf(format, args);
				va_end(args);
			}
			return readCommand();
		}

		static bool readCommand() {
			if (commandQueue.empty()) {
				activateConsole();
				if (fgets(buffer, BUFFER_SIZE, stdin) != NULL) {
					buffer[strcspn(buffer, "\r\n")] = 0;
					return true;
				}
			} else {
				std::string cmd = commandQueue.front();
				commandQueue.pop_front();
				strcpy(buffer, cmd.c_str());
				if (echo_on) {
					printf("%s\n", buffer);
				}
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
						activateGameWindow();
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
				} else if (streq(format, "/c")) {
					datatype = DT_COORDS;
				} else if (streq(format, "/b")) {
					datatype = DT_BOOLEAN;
				} else {
					printf("Invalid format. Valid formats are /f, /d, /c and /b.\n");
					return;
				}
			}
			expression = rawBuffer + (expression - buffer);
			Var* result = datatype == DT_COORDS ? NULL : getVar(currentFrame, expression);
			if (result != NULL) {
				if (datatype == DT_AUTODETECT) {
					datatype = varIsArray(currentFrame, result) ? DT_ARRAY : DT_FLOAT;
				}
			} else {
				int inoutType = datatype;
				result = evalString(currentFrame, expression, inoutType);
				if (datatype == DT_AUTODETECT) {
					datatype = inoutType;
				}
			}
			if (result != NULL) {
				if (datatype == DT_FLOAT) {
					if (result->type == DT_OBJECT) {
						printf("%s%u (object)%s", prefix, result->uintVal, suffix);
					} else {
						printf("%s%f%s", prefix, result->floatVal, suffix);
					}
				} else if (datatype == DT_INT) {
					printf("%s%i%s", prefix, (int)result->floatVal, suffix);
				} else if (datatype == DT_BOOLEAN) {
					printf("%s%s%s", prefix, result->floatVal != 0.0f ? "true" : "false", suffix);
				} else if (datatype == DT_COORDS) {
					printf("%s[%f, %f, %f]%s", prefix, result[0].floatVal, result[1].floatVal, result[2].floatVal, suffix);
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
			const char* cmd = ltrim(argv[0]);
			if (streq(cmd, "") || cmd[0] == '#') {
				return false;
			} else if (streq(cmd, "advance")) {
				return c_advance(rawBuffer, argc, cmd);
			} else if (streq(cmd, "bt") || streq(cmd, "backtrace") || streq(cmd, "where")) {
				return c_backtrace(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "break", 1)) {
				return c_break(rawBuffer, argc, cmd);
			} else if (streq(cmd, "call")) {
				return c_call(rawBuffer, argc, cmd);
			} else if (streq(cmd, "catch")) {
				return c_catch(rawBuffer, argc, cmd);
			} else if (streq(cmd, "clear")) {
				return c_clear(rawBuffer, argc, cmd);
			} else if (streq(cmd, "commands")) {
				return c_commands(rawBuffer, argc, cmd);
			} else if (streq(cmd, "compile")) {
				return c_compile(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "condition", 4)) {
				return c_cond(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "continue", 1)) {
				return c_continue(rawBuffer, argc, cmd);
			} else if (streq(cmd, "define")) {
				return c_define(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "delete", 1)) {
				return c_delete(rawBuffer, argc, cmd);
			} else if (streq(cmd, "detach")) {
				printf("Command not implemented.\n");	//...and will never be!
				return false;
			} else if (abbrev(cmd, "directory", 3)) {
				return c_directory(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "disassemble", 5)) {
				return c_disassemble(rawBuffer, argc, cmd);
			} else if (streq(cmd, "disable")) {
				return c_disable(rawBuffer, argc, cmd);
			} else if (streq(cmd, "display")) {
				return c_display(rawBuffer, argc, cmd);
			} else if (streq(cmd, "down")) {
				return c_down(rawBuffer, argc, cmd);
			} else if (streq(cmd, "down-silently")) {
				return c_down(rawBuffer, argc, cmd);
			} else if (streq(cmd, "echo")) {
				return c_echo(rawBuffer, argc, cmd);
			} else if (streq(cmd, "enable")) {
				return c_enable(rawBuffer, argc, cmd);
			} else if (streq(cmd, "end") && inScript > 0) {
				return c_end(rawBuffer, argc, cmd);
			} else if (streq(cmd, "end_of_script") && inScript > 0) {
				return c_end_of_script(rawBuffer, argc, cmd);
			} else if (streq(cmd, "eval")) {
				return c_eval(rawBuffer, argc, cmd);
			} else if (streq(cmd, "fg")) {
				return c_continue(rawBuffer, argc, cmd);
			} else if (streq(cmd, "finish")) {
				return c_finish(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "frame", 1)) {
				return c_frame(rawBuffer, argc, cmd);
			} else if (streq(cmd, "help")) {
				return c_help(rawBuffer, argc, cmd);
			} else if (streq(cmd, "if") && inScript > 0) {
				return c_if(rawBuffer, argc, cmd);
			} else if (streq(cmd, "ignore")) {
				return c_ignore(rawBuffer, argc, cmd);
			} else if (streq(cmd, "info")) {
				return c_info(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "jump", 1)) {
				return c_jump(rawBuffer, argc, cmd);
			} else if (streq(cmd, "kill")) {
				return c_kill(rawBuffer, argc, cmd);
			} else if (streq(cmd, "list")) {
				return c_list(rawBuffer, argc, cmd);
			} else if (streq(cmd, "loop_break") && inScript > 0) {
				return c_loop_break(rawBuffer, argc, cmd);
			} else if (streq(cmd, "loop_continue") && inScript > 0) {
				return c_loop_continue(rawBuffer, argc, cmd);
			} else if (streq(cmd, "make")) {
				return c_make(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "next", 1)) {
				return c_next(rawBuffer, argc, cmd);
			} else if (streq(cmd, "ni") || streq(cmd, "nexti")) {
				return c_nexti(rawBuffer, argc, cmd);
			} else if (streq(cmd, "output")) {
				return c_output(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "print", 1)) {
				return c_print(rawBuffer, argc, cmd);
			} else if (streq(cmd, "printf")) {
				return c_printf(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "quit", 1)) {
				return c_quit(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "return", 3)) {
				return c_return(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "run", 1)) {
				return c_run(rawBuffer, argc, cmd);
			} else if (streq(cmd, "select-frame")) {
				return c_frame(rawBuffer, argc, cmd);
			} else if (streq(cmd, "set")) {
				return c_set(rawBuffer, argc, cmd);
			} else if (streq(cmd, "shell")) {
				return c_shell(rawBuffer, argc, cmd);
			} else if (streq(cmd, "show")) {
				return c_show(rawBuffer, argc, cmd);
			} else if (streq(cmd, "source")) {
				return c_source(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "step", 1)) {
				return c_step(rawBuffer, argc, cmd);
			} else if (streq(cmd, "si") || streq(cmd, "stepi")) {
				return c_stepi(rawBuffer, argc, cmd);
			} else if (streq(cmd, "tbreak")) {
				return c_break(rawBuffer, argc, cmd);
			} else if (streq(cmd, "thread")) {
				return c_thread(rawBuffer, argc, cmd);
			} else if (streq(cmd, "undisplay")) {
				return c_undisplay(rawBuffer, argc, cmd);
			} else if (abbrev(cmd, "until", 1)) {
				return c_until(rawBuffer, argc, cmd);
			} else if (streq(cmd, "up")) {
				return c_up(rawBuffer, argc, cmd);
			} else if (streq(cmd, "updatechl")) {	//Custom command
				return c_updateChl(rawBuffer, argc, cmd);
			} else if (streq(cmd, "watch")) {
				return c_watch(rawBuffer, argc, cmd);
			} else if (streq(cmd, "whatis")) {
				return c_whatis(rawBuffer, argc, cmd);
			} else if (streq(cmd, "while") && inScript > 0) {
				return c_while(rawBuffer, argc, cmd);
			} else if (streq(cmd, "x")) {
				return c_x(rawBuffer, argc, cmd);
			} else if (cmd[0] == '!') {
				return c_shell(rawBuffer, argc, cmd);
			} else if (userCommands.contains(cmd)) {
				return c_userCommand(rawBuffer, argc, cmd);
			}
			printf("Invalid command '%s'. Enter \"help\" to get a list of available commands.\n", cmd);
			return false;
		}

		static bool c_advance(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_backtrace(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_break(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_call(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
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
			} else {
				printf("Missing argument.\n");
				return false;
			}
		}

		static bool c_catch(char* rawBuffer, int argc, const char* cmd) {
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
					if (argc > 2) {
						for (int j = 2; j < argc; j++) {
							arg = argv[j];
							for (int i = 0; i < NATIVE_COUNT; i++) {
								if (_stricmp(arg, NativeFunctions[i]) == 0) {
									catchSysCalls[i] = ENABLED;
								}
							}
						}
					} else {
						printf("Missing argument.\n");
					}
				} else if (streq(arg, "run")) {
					if (argc > 2) {
						for (int j = 2; j < argc; j++) {
							arg = argv[j];
							Script* script = getScriptByName(arg);
							if (script == NULL) {
								printf("Script '%s' does not exist.\n", arg);
							} else {
								catchRunScripts.insert(arg);
							}
						}
					} else {
						printf("Missing argument.\n");
					}
				} else {
					printf("Invalid event\n");
				}
			}
			return false;
		}

		static bool c_clear(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_commands(char* rawBuffer, int argc, const char* cmd) {
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
				if (breakpoint != NULL) {
					breakpoint->commands = commands;
				}
			}
			return false;
		}

		static bool c_compile(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				if (runningCompileCommand) {
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
					if (expr == NULL) {
						printf("Missing argument.\n");
						return false;
					}
					std::string cmd = "p " + std::string(expr);
					//strcpy(buffer, cmd.c_str());
					//processCommand();
					commandQueue.push_front(cmd);
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
								const char* cmd2 = ltrim(buffer);
								if (streq(cmd2, "end")) break;
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
							printf("File '%s' not found.\n", expr);
							return false;
						} else {
							auto filelines = readFile(absFilename);
							lines.insert(lines.end(), filelines.begin(), filelines.end());
						}
					} else {
						printf("Expected 'code' or 'file'.\n");
						return false;
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
							resumeThreadId = currentFrame != NULL ? getThread(currentFrame)->taskNumber : 0;
							runningCompileCommand = true;
							compiledThreadId = ScriptLibraryR.StartScript(0, "_gdb_expr_", -1);
							allowedThreadId = compiledThreadId;
							return true;
						}
					}
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_cond(char* rawBuffer, int argc, const char* cmd) {
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
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_continue(char* rawBuffer, int argc, const char* cmd) {
			//continue running the program
			if (argc == 2 && lastHitBreakpoint != NULL) {
				lastHitBreakpoint->targetHitCount = atoi(argv[1]);
				lastHitBreakpoint->hits = 0;
			}
			printf("Continuing.\n");
			return true;
		}

		static bool c_define(char* rawBuffer, int argc, const char* cmd) {
			if (argc == 2) {
				const char* name = argv[1];
				auto& ucmd = userCommands[name];
				ucmd.commands.clear();
				int depth = 1;
				bool inCompile = false;
				while (prompt(">")) {
					const char* cmd2 = ltrim(buffer);
					if (!inCompile && (strncmp(cmd2, "if ", 3) == 0 || strncmp(cmd2, "while ", 6) == 0)) {
						depth++;
					} else if (strncmp(cmd2, "compile ", 8) == 0 && std::string(buffer).ends_with(" --")) {
						inCompile = true;
						depth++;
					} else if (streq(cmd2, "end")) {
						inCompile = false;
						depth--;
						if (depth == 0) break;
					}
					ucmd.commands.push_back(buffer);
				}
				ucmd.commands.push_back("end_of_script");
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_delete(char* rawBuffer, int argc, const char* cmd) {
			if (argc == 1) {
				prompt("Delete all breakpoints? (y or n) ");
				if (streq(buffer, "y")) {
					for (Breakpoint* breakpoint : getBreakpoints()) {
						unsetBreakpoint(breakpoint);
					}
				}
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
						if (catchThread != NULL && index-- == 0) {
							catchThread = NULL;
						} else {
							for (int i = 0; i < NATIVE_COUNT; i++) {
								if (catchSysCalls[i]) {
									if (index-- == 0) {
										catchSysCalls[i] = NOT_SET;
										return false;
									}
								}
							}
							if (index < (int)catchRunScripts.size()) {
								auto it = catchRunScripts.begin();
								std::advance(it, index);
								catchRunScripts.erase(it);
							} else {
								index -= catchRunScripts.size();
								printf("Breakpoint not found\n");
							}
						}
					}
				}
			}
			return false;
		}

		static bool c_directory(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				//dir names
				//  add directory names to front of source path
				for (int i = 1; i < argc; i++) {
					sourcePath.insert(argv[i]);
				}
				unsetMissingSources();	//There are chances that we can find sources now
			} else {
				//dir
				//  clear source path
				sourcePath.clear();
			}
			return false;
		}

		static bool c_disassemble(char* rawBuffer, int argc, const char* cmd) {
			const int count = getTotalInstructions();
			int ip = -1;
			int startIp = -1;
			int endIp = -1;
			Script unknownScript;
			unknownScript.name = (char*)"0";
			unknownScript.filename = (char*)"";
			unknownScript.instructionAddress = 0;
			Script* script = NULL;
			bool withSource = getArgFlag(argv, argc, "/m") || getArgFlag(argv, argc, "/s");
			bool printFuncName = false;
			const char* funcName = "";
			for (int i = 1; i < argc; i++) {
				if (argv[i][0] != '/') {
					char* arg = argv[i];
					arg = rawBuffer + (arg - buffer);
					argc = splitArgs(arg, ',', argv, 2);
					if (streq(argv[0], "$ip")) {
						if (currentFrame == NULL) {
							printf("No active frame.\n");
							return false;
						}
						ip = currentFrame->ip;
					} else {
						ip = atoi(argv[0]);
					}
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
						if (endIp <= startIp) {
							printf("Invalid end instruction address.\n");
							return false;
						}
						if (endIp > count) {
							endIp = count;
						}
						script = findScriptByIp(startIp);
						if (script == NULL) script = &unknownScript;
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
				startIp = script != NULL ? script->instructionAddress : ip;
				endIp = findInstruction(ip, END) + 1;
				if (script == NULL) script = &unknownScript;
			}
			printf("Dump of assembler code from %i to %i:\n", startIp, endIp);
			int lastDisplayedLine = 0;
			const int width = snprintf(NULL, 0, "%i", endIp);
			for (int ip = startIp; ip < endIp; ip++) {
				if (script == NULL) {
					script = findScriptByIp(ip);
					if (script == NULL) script = &unknownScript;
					funcName = script->name;
				}
				Instruction* instr = getInstruction(ip);
				if (withSource && script != &unknownScript && instr->linenumber != lastDisplayedLine) {
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
		}

		static bool c_disable(char* rawBuffer, int argc, const char* cmd) {
			if (argc == 1) {
				for (Breakpoint* breakpoint : getBreakpoints()) {
					breakpoint->setEnabled(false);
				}
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
			} else {
				int index = atoi(argv[argc - 1]) - 1;
				if (index < 0) {
					printf("Invalid index\n");
					return false;
				}
				auto breakpoints = getBreakpoints();
				if (index < (int)breakpoints.size()) {
					Breakpoint* breakpoint = getBreakpointByIndex(index);
					breakpoint->setEnabled(false);
				} else {
					index -= breakpoints.size();
					auto watches = getWatches();
					if (index < (int)watches.size()) {
						Watch* watch = getWatchByIndex(index);
						watch->setEnabled(false);
					} else {
						index -= watches.size();
						if (catchThread != NULL && index-- == 0) {
							printf("Catchpoint for exceptions can't be disabled, please use delete command.\n");
						} else {
							for (int i = 0; i < NATIVE_COUNT; i++) {
								if (catchSysCalls[i]) {
									if (index-- == 0) {
										catchSysCalls[i] = DISABLED;
										return false;
									}
								}
							}
							if (index < (int)catchRunScripts.size()) {
								printf("Catchpoint for run can't be disabled, please use delete command.\n");
							} else {
								index -= catchRunScripts.size();
								printf("Breakpoint not found\n");
							}
						}
					}
				}
			}
			return false;
		}

		static bool c_display(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_down(char* rawBuffer, int argc, const char* cmd) {
			int n = argc == 2 ? atoi(argv[1]) : 1;
			moveFrame(-n, strstr(cmd, "-silently") != NULL);
			return false;
		}

		static bool c_echo(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_enable(char* rawBuffer, int argc, const char* cmd) {
			if (argc == 1) {
				for (Breakpoint* breakpoint : getBreakpoints()) {
					breakpoint->setEnabled(true);
				}
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
			} else {
				bool once = getArgFlag(argv, argc, "once");
				bool deleteOnHit = getArgFlag(argv, argc, "del");
				int index = atoi(argv[argc - 1]) - 1;
				if (index < 0) {
					printf("Invalid index\n");
					return false;
				}
				auto breakpoints = getBreakpoints();
				if (index < (int)breakpoints.size()) {
					Breakpoint* breakpoint = getBreakpointByIndex(index);
					breakpoint->setEnabled(true);
					if (once) {
						breakpoint->targetHitCount = 1;
					}
					if (deleteOnHit) {
						breakpoint->deleteOnHit = true;
					}
				} else {
					index -= breakpoints.size();
					auto watches = getWatches();
					if (index < (int)watches.size()) {
						Watch* watch = getWatchByIndex(index);
						watch->setEnabled(true);
					} else {
						index -= watches.size();
						if (catchThread != NULL && index-- == 0) {
							//can't be disabled, just deleted
						} else {
							for (int i = 0; i < NATIVE_COUNT; i++) {
								if (catchSysCalls[i]) {
									if (index-- == 0) {
										catchSysCalls[i] = ENABLED;
										return false;
									}
								}
							}
							if (index < (int)catchRunScripts.size()) {
								//can't be disabled, just deleted
							} else {
								index -= catchRunScripts.size();
								printf("Breakpoint not found\n");
							}
						}
					}
				}
			}
			return false;
		}

		static bool c_end(char* rawBuffer, int argc, const char* cmd) {
			if (blocks.empty()) {
				printf("'end' unexpected.\n");
			} else {
				blocks.pop_back();
			}
			return false;
		}

		static bool c_end_of_script(char* rawBuffer, int argc, const char* cmd) {
			inScript--;
			return false;
		}

		static bool c_eval(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				char* sArgs = strchr(rawBuffer, ' ') + 1;
				argc = splitArgs(sArgs, ',', argv, MAX_ARGS);
				char* format = argv[0];
				char line[1024];
				int len = usprintf(line, argv[0], argc - 1, argv + 1);
				if (len > 0) {
					commandQueue.push_front(line);
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_finish(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_frame(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_if(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				blocks.push_back(BLOCK);
				char* sCond = rawBuffer + (argv[1] - buffer);
				int datatype = DT_BOOLEAN;
				Script* script = getTaskScript(currentFrame);
				Expression* cond = getCompiledExpression(script, sCond, datatype);
				if (cond != NULL) {
					std::list<std::string> lines;
					Var* condRes = evalExpression(currentFrame, cond);
					bool condVal = condRes != NULL && condRes->floatVal != 0;
					bool inThen = true;
					int depth = 1;
					while (true) {
						prompt(">");
						const char* cmd2 = ltrim(buffer);
						if (strncmp(cmd2, "if ", 3) == 0 || strncmp(cmd2, "while ", 6) == 0) {
							depth++;
						} else if (depth == 1 && streq(cmd2, "else")) {
							inThen = false;
							continue;
						} else if (streq(cmd2, "end")) {
							depth--;
							if (depth == 0) break;
						}
						if (condVal == inThen) {
							lines.push_back(buffer);
						}
					}
					lines.push_back("end");
					commandQueue.insert(commandQueue.begin(), lines.begin(), lines.end());
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_ignore(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 3) {
				int index = atoi(argv[1]) - 1;
				int count = atoi(argv[2]);
				Breakpoint* breakpoint = getBreakpointByIndex(index);
				if (breakpoint != NULL) {
					breakpoint->setEnabled(true);
					breakpoint->targetHitCount = count + 1;
				} else {
					printf("Breakpoint not found\n");
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_info(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				const char* arg = argv[1];
				if (streq(arg, "address")) {
					return c_info_address(rawBuffer, argc, cmd);
				} else if (streq(arg, "args")) {
					return c_info_args(rawBuffer, argc, cmd);
				} else if (abbrev(arg, "breakpoints", 5)) {
					return c_info_breakpoints(rawBuffer, argc, cmd);
				} else if (streq(arg, "display")) {
					return c_info_display(rawBuffer, argc, cmd);
				} else if (streq(arg, "func")) {
					return c_info_func(rawBuffer, argc, cmd);
				} else if (streq(arg, "locals")) {
					return c_info_locals(rawBuffer, argc, cmd);
				} else if (abbrev(arg, "reg", 1)) {
					return c_info_reg(rawBuffer, argc, cmd);
				} else if (streq(arg, "source")) {
					return c_info_source(rawBuffer, argc, cmd);
				} else if (streq(arg, "sources")) {
					return c_info_sources(rawBuffer, argc, cmd);
				} else if (streq(arg, "threads")) {
					return c_info_threads(rawBuffer, argc, cmd);
				} else if (streq(arg, "var")) {
					return c_info_var(rawBuffer, argc, cmd);
				} else {
					printf("Invalid argument.\n");
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_info_address(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 3) {
				//info address s
				//  show where symbol s is stored
				char* arg = argv[2];
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
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_info_args(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_info_breakpoints(char* rawBuffer, int argc, const char* cmd) {
			//info breakpoints
			//  show defined breakpoints
			int index = 1;
			for (Breakpoint* breakpoint : getBreakpoints()) {
				const char* enabled = breakpoint->isEnabled() ? "enabled" : "disabled";
				printf("%5i breakpoint %-8s %8i %s:%i\n", index++, enabled, breakpoint->ip,
					breakpoint->filename.c_str(), breakpoint->lineno);
			}
			for (Watch* watch : getWatches()) {
				const char* enabled = watch->isEnabled() ? "enabled" : "disabled";
				if (watch->task == NULL) {
					printf("%5i watchpoint %-8s %8i %s\n", index++, enabled, 0, watch->getExpression()->str.c_str());
				} else {
					printf("%5i watchpoint %-8s %8i %s (Task %i)\n", index++, enabled, 0,
						watch->getExpression()->str.c_str(), watch->task->taskNumber);
				}
			}
			if (catchThread != NULL) {
				printf("%5i catchpoint %-8s %8i %s (Thread %i)\n", index++, "enabled", 0, "exception", catchThread->taskNumber);
			}
			for (int i = 0; i < NATIVE_COUNT; i++) {
				if (catchSysCalls[i]) {
					const char* enabled = catchSysCalls[i] == ENABLED ? "enabled" : "disabled";
					printf("%5i catchpoint %-8s %8i %s\n", index++, enabled, 0, NativeFunctions[i]);
				}
			}
			for (std::string name : catchRunScripts) {
				printf("%5i catchpoint %-8s %8i %s %s\n", index++, "enabled", 0, "run", name.c_str());
			}
			return false;
		}

		static bool c_info_display(char* rawBuffer, int argc, const char* cmd) {
			int i = 1;
			for (Display* display : displays) {
				const char* enabled = display->enabled ? "" : " (disabled)";
				printf("%3i: %s%s\n", i++, display->expression.c_str(), enabled);
			}
			return false;
		}

		static bool c_info_func(char* rawBuffer, int argc, const char* cmd) {
			std::regex pattern;
			if (argc >= 3) {
				try {
					pattern = std::regex(argv[2], std::regex::icase);
				} catch (std::regex_error& e) {
					printf("Invalid regex: %s.\n", e.what());
					return false;
				}
			} else {
				pattern = std::regex(".*", std::regex::icase);
			}
			for (Script* script : getScripts()) {
				if (std::regex_search(script->name, pattern)) {
					std::string params = "";
					if (script->parameterCount > 0) {
						params = script->localVars.pFirst[0]->name;
						for (DWORD i = 1; i < script->parameterCount; i++) {
							params += ", " + std::string(script->localVars.pFirst[i]->name);
						}
					}
					Instruction* instr = getInstruction(script->instructionAddress);
					printf("%i: %s(%s) at %i from '%s:%i'\n", script->id, script->name, params.c_str(),
							script->instructionAddress, script->filename, instr->linenumber);
				}
			}
			return false;
		}

		static bool c_info_locals(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_info_reg(char* rawBuffer, int argc, const char* cmd) {
			//info reg [rn]
			//  register values [for regs rn] in selected frame
			if (currentFrame == NULL) {
				printf("No frame selected.");
				return false;
			}
			#define PR_REG(REG, EXPR) if (argc <= 2 || inArray(REG, argv+2, argc-2)) printf("%-3s %9i\n", REG, EXPR);
			PR_REG("ip", currentFrame->ip);
			PR_REG("ba", currentFrame->instructionAddress);
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
		}

		static bool c_info_source(char* rawBuffer, int argc, const char* cmd) {
			//info source
			//  show name of current source file
			if (currentFrame != NULL) {
				printf("%s\n", currentFrame->filename);
			} else {
				printf("No frame selected.\n");
			}
			return false;
		}

		static bool c_info_sources(char* rawBuffer, int argc, const char* cmd) {
			//info sources
			//  list all source files in use
			std::unordered_set<std::string> printed;
			ScriptEntry* scriptEntry = ScriptLibraryR.pScriptList->pFirst;
			while (scriptEntry != NULL) {
				Script* script = scriptEntry->script;
				if (!printed.contains(script->filename)) {
					printf("%s\n", script->filename);
					printed.insert(script->filename);
				}
				scriptEntry = scriptEntry->next;
			}
			return false;
		}

		static bool c_info_threads(char* rawBuffer, int argc, const char* cmd) {
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

		static bool c_info_var(char* rawBuffer, int argc, const char* cmd) {
			std::regex pattern;
			if (argc >= 3) {
				try {
					pattern = std::regex(argv[2], std::regex::icase);
				} catch (std::regex_error& e) {
					printf("Invalid regex: %s.\n", e.what());
					return false;
				}
			} else {
				pattern = std::regex(".*", std::regex::icase);
			}
			for (VarDef var : getGlobalVarDefs()) {
				if (std::regex_search(var.name, pattern)) {
					if (var.size == 1) {
						printf("%i: %s\n", var.id, var.name.c_str());
					} else {
						printf("%i: %s[%i]\n", var.id, var.name.c_str(), var.size);
					}
				}
			}
			return false;
		}

		static bool c_jump(char* rawBuffer, int argc, const char* cmd) {
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
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_kill(char* rawBuffer, int argc, const char* cmd) {
			//kill running program
			ExitProcess(1);
			return false;
		}

		static bool c_list(char* rawBuffer, int argc, const char* cmd) {
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
					first = atoi(argv[argc - 1]) - 6;
					last = first + 9;
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
		}

		static bool c_loop_break(char* rawBuffer, int argc, const char* cmd) {
			bool found = false;
			int rdepth = 1;
			for (auto it = blocks.rbegin(); it != blocks.rend(); it++, rdepth++) {
				if (*it == LOOP) {
					found = true;
					break;
				}
			}
			if (!found) {
				printf("Not in a loop.\n");
				return false;
			}
			//Remove the running loop
			while (!commandQueue.empty()) {
				std::string line = commandQueue.front();
				commandQueue.pop_front();
				const char* cmd2 = ltrim(line.c_str());
				if (strncmp(cmd2, "if ", 3) == 0 || strncmp(cmd2, "while ", 6) == 0) {
					rdepth++;
				} else if (streq(cmd2, "end")) {
					rdepth--;
					if (rdepth == 0) {
						blocks.pop_back();
						break;
					}
				}
			}
			//Remove the next loop
			while (!commandQueue.empty()) {
				std::string line = commandQueue.front();
				commandQueue.pop_front();
				const char* cmd2 = ltrim(line.c_str());
				if (strncmp(cmd2, "if ", 3) == 0 || strncmp(cmd2, "while ", 6) == 0) {
					rdepth++;
				} else if (streq(cmd2, "end")) {
					rdepth--;
					if (rdepth == 0) break;
				}
			}
			return false;
		}

		static bool c_loop_continue(char* rawBuffer, int argc, const char* cmd) {
			bool found = false;
			int rdepth = 1;
			for (auto it = blocks.rbegin(); it != blocks.rend(); it++, rdepth++) {
				if (*it == LOOP) {
					found = true;
					break;
				}
			}
			if (!found) {
				printf("Not in a loop.\n");
				return false;
			}
			//Remove the running loop
			while (!commandQueue.empty()) {
				std::string line = commandQueue.front();
				commandQueue.pop_front();
				const char* cmd2 = ltrim(line.c_str());
				if (strncmp(cmd2, "if ", 3) == 0 || strncmp(cmd2, "while ", 6) == 0) {
					rdepth++;
				} else if (streq(cmd2, "end")) {
					rdepth--;
					if (rdepth == 0) {
						blocks.pop_back();
						break;
					}
				}
			}
			return false;
		}

		static bool c_make(char* rawBuffer, int argc, const char* cmd) {
			Var* var = getGlobalVarById(shell_exitcode_id);
			const char* arg = ltrim(rawBuffer);
			int r = system(arg);
			if (var != NULL) var->floatVal = (float)r;
			return false;
		}

		static bool c_next(char* rawBuffer, int argc, const char* cmd) {
			if (currentFrame != NULL) {
				breakFromAddress = 0x7FFFFFFF;
				breakAfterLines = argc >= 2 ? atoi(argv[1]) : 1;
				steppingThread = getThread(currentFrame);
				stepInMaxDepth = getFrameDepth(currentFrame);
				return true;
			} else {
				printf("Execution must be paused to step\n");
				return false;
			}
		}

		static bool c_nexti(char* rawBuffer, int argc, const char* cmd) {
			if (currentFrame != NULL) {
				breakFromAddress = 0x7FFFFFFF;
				breakAfterInstructions = argc >= 2 ? atoi(argv[1]) : 1;
				steppingThread = getThread(currentFrame);
				stepInMaxDepth = getFrameDepth(currentFrame);
				return true;
			} else {
				printf("Execution must be paused to step\n");
				return false;
			}
		}

		static bool c_output(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				uprint(rawBuffer, "", "");
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_print(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				uprint(rawBuffer, "$1 = ", "\n");
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_printf(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				char* sArgs = strchr(rawBuffer, ' ') + 1;
				argc = splitArgs(sArgs, ',', argv, MAX_ARGS);
				char* format = argv[0];
				char line[1024];
				int len = usprintf(line, argv[0], argc - 1, argv + 1);
				if (len >= 0) {
					printf("%s", line);
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_quit(char* rawBuffer, int argc, const char* cmd) {
			//quit
			ExitProcess(1);
			return false;
		}

		static bool c_return(char* rawBuffer, int argc, const char* cmd) {
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
					//TODO: the execution should stop in the caller task

					currentFrame->ip = ip;
					printCurrentInstruction(currentFrame);
				}
			}
			return false;
		}

		static bool c_run(char* rawBuffer, int argc, const char* cmd) {
			printf("Continuing.\n");
			return true;
		}

		static bool c_set(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				char* type = argv[1];
				if (streq(type, "echo") && argc == 3) {
					char* val = argv[2];
					if (streq(val, "on")) {
						echo_on = true;
						printf("echo is on.\n");
					} else if (streq(val, "off")) {
						echo_on = false;
					} else {
						printf("Expected 'on' or 'off'.\n");
					}
					return false;
				} else if (streq(type, "print") && argc == 4) {
					char* prop = argv[2];
					char* sVal = argv[3];
					if (streq(prop, "elements")) {
						maxPrintElements = atoi(sVal);
						maxPrintElements = MAX(1, maxPrintElements);
					} else {
						printf("Invalid property.\n");
					}
					return false;
				} else if (streq(type, "console")) {
					return c_set_console(rawBuffer, argc, cmd);
				} else if (streq(type, "window")) {
					return c_set_window(rawBuffer, argc, cmd);
				} else if (abbrev(type, "instruction", 5)) {
					return c_set_instruction(rawBuffer, argc, cmd);
				} else {
					return c_set_variable(rawBuffer, argc, cmd);
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_set_console(char* rawBuffer, int argc, const char* cmd) {
			if (argc < 3) {
				printf("Missing argument.\n");
				return false;
			}
			char* prop = argv[2];
			if (abbrev(prop, "position", 3)) {
				if (argc < 4) {
					printf("Missing argument.\n");
					return false;
				}
				char* sVal = argv[3];
				setWindowPos(consoleWindow, sVal);
			} else if (streq(prop, "size")) {
				if (argc < 4) {
					printf("Missing argument.\n");
					return false;
				}
				char* sVal = argv[3];
				argc = splitArgs(sVal, ',', argv, 2);
				if (argc == 2) {
					int w = atoi(argv[0]);
					int h = atoi(argv[1]);
					if (w < 200) w = 200;
					if (h < 100) h = 100;
					SetWindowPos(consoleWindow, NULL, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
				} else {
					printf("Invalid size.\n");
				}
			} else if (streq(prop, "topmost")) {
				SetWindowPos(consoleWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
			} else if (streq(prop, "notopmost")) {
				SetWindowPos(consoleWindow, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
			} else if (streq(prop, "maximize")) {
				ShowWindow(consoleWindow, SW_MAXIMIZE);
			} else if (streq(prop, "minimize")) {
				ShowWindow(consoleWindow, SW_MINIMIZE);
			} else if (streq(prop, "restore")) {
				ShowWindow(consoleWindow, SW_RESTORE);
			} else {
				printf("Invalid property.\n");
			}
			return false;
		}

		static bool c_set_window(char* rawBuffer, int argc, const char* cmd) {
			if (argc < 3) {
				printf("Missing argument.\n");
				return false;
			}
			char* prop = argv[2];
			if (abbrev(prop, "position", 3)) {
				if (argc < 4) {
					printf("Missing argument.\n");
					return false;
				}
				char* sVal = argv[3];
				setWindowPos(gameWindow, sVal);
			} else if (streq(prop, "topmost")) {
				SetWindowPos(gameWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
			} else if (streq(prop, "notopmost")) {
				SetWindowPos(gameWindow, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
			} else if (streq(prop, "minimize")) {
				ShowWindow(gameWindow, SW_MINIMIZE);
			} else if (streq(prop, "restore")) {
				ShowWindow(gameWindow, SW_RESTORE);
			} else {
				printf("Invalid property.\n");
			}
			return false;
		}

		static void setWindowPos(const HWND hwnd, char* sVal) {
			if (streq(sVal, "tl")) {
				alignWindow(hwnd, NULL, Anchor::TOP_LEFT);
			} else if (streq(sVal, "tr")) {
				alignWindow(hwnd, NULL, Anchor::TOP_RIGHT);
			} else if (streq(sVal, "br")) {
				alignWindow(hwnd, NULL, Anchor::BOTTOM_RIGHT);
			} else if (streq(sVal, "bl")) {
				alignWindow(hwnd, NULL, Anchor::BOTTOM_LEFT);
			} else {
				int argc = splitArgs(sVal, ',', argv, 2);
				if (argc == 2) {
					int x = atoi(argv[0]);
					int y = atoi(argv[1]);
					SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
				} else {
					printf("Invalid coordinates.\n");
				}
			}
		}

		static bool c_set_instruction(char* rawBuffer, int argc, const char* cmd) {
			#ifdef CHL_ASSEMBLER
				if (argc < 3) {
					printf("Expected expression\n.");
					return false;
				}
				char* sExpr = argv[2];
				sExpr = rawBuffer + (sExpr - buffer);
				if (strchr(sExpr, '=') != NULL) {
					splitArgs(sExpr, '=', argv, 2);
					char* sAddr = argv[0];
					char* sValue = argv[1];
					int base = 0;
					char* sOffset = strchr(sAddr, '+');
					if (sOffset == NULL) sOffset = sAddr;
					if (sOffset > sAddr) {
						*(sOffset++) = 0;	//Split base from offset
						if (streq(sAddr, "$ip")) {
							if (currentFrame == NULL) {
								printf("No active frame.\n");
								return false;
							}
							base = currentFrame->ip;
						} else if (streq(sAddr, "$ba")) {
							if (currentFrame == NULL) {
								printf("No active frame.\n");
								return false;
							}
							base = currentFrame->instructionAddress;
						} else {
							Script* script = getScriptByName(sAddr);
							if (script == NULL) {
								printf("Script '%s' not found.\n", sAddr);
								return false;
							}
							base = script->instructionAddress;
						}
					}
					if (!isNumber(sOffset)) {
						printf("Invalid offset.\n");
						return false;
					}
					int addr = base + atoi(sOffset);
					if (addr < 0 || addr >= getTotalInstructions()) {
						printf("Invalid address.\n");
						return false;
					}
					Script* script = findScriptByIp(addr);
					if (script == NULL) {
						printf("Cannot determine script at instruction %i.\n", addr);
						return false;
					}
					const char* msg = assemble(script, addr, sValue);
					if (msg != NULL) {
						printf("Assembler error: %s\n", msg);
					}
				} else {
					printf("Expected =\n");
				}
			#else
				printf("gdb has been compiled without assembler\n.");
			#endif
			return false;
		}

		static bool c_set_variable(char* rawBuffer, int argc, const char* cmd) {
			char* sExpr = argv[1];
			if (streq(sExpr, "var") || streq(sExpr, "variable")) {
				if (argc < 3) {
					printf("Expected expression\n.");
					return false;
				}
				sExpr = argv[2];
			}
			sExpr = rawBuffer + (sExpr - buffer);
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
					Var* var;
					if (strncmp(name, "{int}", 5) == 0) {
						int varId = atoi(name + 5);
						var = getVarById(currentFrame, varId);
						if (var == NULL) {
							printf("Invalid variable ID.\n");
							return false;
						}
					} else {
						var = getVar(currentFrame, name);
						if (var == NULL && name[0] == '_') {
							int gVarId = declareGlobalVar(name, 1, 0.0);
							printf("Global variable '%s' defined with ID %i\n", name, gVarId);
						}
					}
					if (var != NULL) {
						if (var->type == DataTypes::DT_OBJECT) {
							ScriptLibraryR.removeReference(var->uintVal);
						}
						if (streq(sValue, "true")) {
							var->type = DataTypes::DT_FLOAT;
							var->floatVal = 1.0;
						} else if (streq(sValue, "false")) {
							var->type = DataTypes::DT_FLOAT;
							var->floatVal = 0.0;
						} else if (strncmp(sValue, "(object)", 8) == 0) {
							char* sNum = sValue + 8;
							if (isNumber(sNum)) {
								var->type = DT_OBJECT;
								var->uintVal = (DWORD)atoll(sNum);
							} else {
								printf("Invalid number.\n");
							}
						} else {
							int datatype = DT_FLOAT;
							Var* res = evalString(currentFrame, sValue, datatype);
							if (res != NULL) {
								var->type = res->type;
								var->uintVal = res->uintVal;
							}
						}
						if (var->type == DataTypes::DT_OBJECT) {
							ScriptLibraryR.addReference(var->uintVal);
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
			return false;
		}

		static bool c_shell(char* rawBuffer, int argc, const char* cmd) {
			Var* var = getGlobalVarById(shell_exitcode_id);
			if (cmd[0] == '!') {
				const char* arg = rawBuffer + (cmd + 1 - buffer);
				int r = system(arg);
				if (var != NULL) var->floatVal = (float)r;
			} else if (argc >= 2) {
				const char* arg = rawBuffer + (argv[1] - buffer);
				int r = system(arg);
				if (var != NULL) var->floatVal = (float)r;
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_show(char* rawBuffer, int argc, const char* cmd) {
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
				} else if (streq(arg, "console")) {
					ShowWindow(consoleWindow, SW_SHOW);
				} else if (streq(arg, "window")) {
					ShowWindow(gameWindow, SW_SHOW);
				} else {
					printf("Invalid argument.\n");
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_source(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				char* filename = argv[1];
				filename = rawBuffer + (filename - buffer);
				//rejoinArgs(argv, argc, filename, NULL);
				std::string absFilename = searchPaths(sourcePath, filename);
				if (absFilename == "") {
					printf("File '%s' not found.\n", filename);
				} else {
					FILE* file = fopen(absFilename.c_str(), "rt");
					if (file == NULL) {
						printf("Failed to open file '%s'\n", absFilename.c_str());
					} else {
						auto it = commandQueue.begin();
						while (fgets(buffer, BUFFER_SIZE, file)) {
							buffer[strcspn(buffer, "\r\n")] = 0;
							commandQueue.insert(it, buffer);
						}
						fclose(file);
						commandQueue.insert(it, "end_of_script");
						inScript++;
					}
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_step(char* rawBuffer, int argc, const char* cmd) {
			//step [count]
			//  execute until another line reached; repeat count times if specified
			if (currentFrame != NULL) {
				breakFromAddress = 0x7FFFFFFF;
				breakAfterLines = argc >= 2 ? atoi(argv[1]) : 1;
				steppingThread = getThread(currentFrame);
				stepInMaxDepth = 9999;
				return true;
			} else {
				printf("Execution must be paused to step\n");
				return false;
			}
		}

		static bool c_stepi(char* rawBuffer, int argc, const char* cmd) {
			//stepi
			//  step by machine instructions rather than source lines
			if (currentFrame != NULL) {
				breakFromAddress = 0x7FFFFFFF;
				breakAfterInstructions = argc >= 2 ? atoi(argv[1]) : 1;
				steppingThread = getThread(currentFrame);
				stepInMaxDepth = 9999;
				return true;
			} else {
				printf("Execution must be paused to step\n");
				return false;
			}
		}

		static bool c_thread(char* rawBuffer, int argc, const char* cmd) {
			if (argc == 2) {
				int threadId = atoi(argv[1]);
				auto threads = getThreads();
				if (threadId < 1 || threadId >(int)threads.size()) {
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
			} else {
				printf("Missing argument.\n");
				return false;
			}
		}

		static bool c_undisplay(char* rawBuffer, int argc, const char* cmd) {
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
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_until(char* rawBuffer, int argc, const char* cmd) {
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
		}

		static bool c_up(char* rawBuffer, int argc, const char* cmd) {
			int n = argc == 2 ? atoi(argv[1]) : 1;
			moveFrame(n, strstr(cmd, "-silently") != NULL);
			return false;
		}

		static bool c_updateChl(char* rawBuffer, int argc, const char* cmd) {
			const char* filename = getArgVal(argv, argc, "-f");
			char* stopMode = getArgValOrDefault(argv, argc, "-stop", "script");
			char* restart = getArgVal(argv, argc, "-r");
			bool stopAllInChangedFiles = streq(stopMode, "file");
			captureKilledThreads = true;
			if (updateCHL(filename, stopAllInChangedFiles)) {
				if (!killedThreads.empty()) {
					int r = 0;
					while (r == 0) {
						if (restart == NULL) {
							prompt("Do you want to restart previous threads? (yes/no/all) ");
						} else {
							strcpy(buffer, restart);
							restart = NULL;
						}
						if (abbrev(buffer, "yes", 1)) {
							r = 1;
						} else if (abbrev(buffer, "no", 1)) {
							r = 2;
						} else if (abbrev(buffer, "all", 1)) {
							r = 3;
						}
					}
					if (r != 2) {
						for (auto info : killedThreads) {
							Script* script = getScriptByName(info.name);
							if (script != NULL) {
								int r2 = r == 3 ? 1 : 0;
								while (r2 == 0) {
									prompt("Restart %s(%s)? y or n ", info.name.c_str(), info.formatParameters().c_str());
									if (abbrev(buffer, "yes", 1)) {
										r2 = 1;
									} else if (abbrev(buffer, "no", 1)) {
										r2 = 2;
									}
								}
								if (r2 == 1) {
									//Push parameters on the stack
									for (auto& param : info.parameters) {
										ScriptLibraryR.PUSH(param.floatVal, param.type);
									}
									//Start the script
									int taskNumber = ScriptLibraryR.StartScript(NULL, info.name.c_str(), 0xFFFFFFFF);
									if (taskNumber == 0) {
										printf("Failed to start script %s\n", info.name.c_str());
									}
								}
							} else {
								printf("Script '%s' has been removed\n", info.name.c_str());
							}
						}
					}
					killedThreads.clear();
				}
			}
			captureKilledThreads = false;
			return false;
		}

		static bool c_watch(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				const char* sExpr = argv[1];
				sExpr = rawBuffer + (sExpr - buffer);
				addWatch(currentFrame, sExpr);
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_whatis(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				const char* sExpr = argv[1];
				sExpr = rawBuffer + (sExpr - buffer);
				Script* script = getTaskScript(currentFrame);
				Expression* expr = getCompiledExpression(script, sExpr, DT_AUTODETECT);
				if (expr != NULL) {
					printf("%s\n", datatype_names[expr->datatype]);
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_while(char* rawBuffer, int argc, const char* cmd) {
			if (argc >= 2) {
				blocks.push_back(LOOP);
				char* sCond = rawBuffer + (argv[1] - buffer);
				int datatype = DT_BOOLEAN;
				Script* script = getTaskScript(currentFrame);
				Expression* cond = getCompiledExpression(script, sCond, datatype);
				if (cond != NULL) {
					std::list<std::string> lines;
					int depth = 1;
					while (depth > 0) {
						prompt(">");
						const char* cmd2 = ltrim(buffer);
						if (strncmp(cmd2, "if ", 3) == 0 || strncmp(cmd2, "while ", 6) == 0) {
							depth++;
						} else if (streq(cmd2, "end")) {
							depth--;
						}
						lines.push_back(buffer);
					}
					Var* condRes = evalExpression(currentFrame, cond);
					if (condRes != NULL && condRes->floatVal != 0.0) {	//If condition is true
						auto it = commandQueue.begin();
						//Add the instructions to be executed on this iteration
						commandQueue.insert(it, lines.begin(), lines.end());
						//Add the while-end block again for the next iteration
						commandQueue.insert(it, rawBuffer);	//while condition
						commandQueue.insert(it, lines.begin(), lines.end());
					}
				}
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_x(char* rawBuffer, int argc, const char* cmd) {
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
							case DT_OBJECT:
								printf("%2i: %c %u\n", i, datatype_chars[type], currentFrame->stack.uintVals[i]);
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
			} else {
				printf("Missing argument.\n");
			}
			return false;
		}

		static bool c_help(char* rawBuffer, int argc, const char* cmd) {
			if (argc < 2) {
				//TODO
				printf("Help not available\n");
			} else {
				char* topic = argv[1];
				//TODO
				printf("Help for \"%s\" not available\n", topic);
			}
			return false;
		}

		static bool c_userCommand(char* rawBuffer, int argc, const char* cmd) {
			auto it = commandQueue.begin();
			auto& ucmd = userCommands[cmd];
			for (auto line : ucmd.commands) {
				for (int i = argc - 1; i > 0; i--) {
					line = strReplace(line, "$arg" + std::to_string(i - 1), argv[i]);
				}
				commandQueue.insert(it, line);
			}
			inScript++;
			return false;
		}
};

char Gdb::buffer[BUFFER_SIZE];
char* Gdb::argv[MAX_ARGS];

std::list<std::string> Gdb::commandQueue = std::list<std::string>();

Breakpoint* Gdb::lastHitBreakpoint;

char Gdb::lastPrintedFile[256];
int Gdb::firstPrintedLine = 0;
int Gdb::lastPrintedLine = 0;
Task* Gdb::lastPrintedLineTask = NULL;
int Gdb::lastPrintedLineIp = -1;

Task* Gdb::currentFrame = NULL;
int Gdb::compiledThreadId = 0;
int Gdb::resumeThreadId = 0;
bool Gdb::runningCompileCommand = false;

std::list<Display*> Gdb::displays = std::list<Display*>();

std::map<std::string, UserCommand> Gdb::userCommands = std::map<std::string, UserCommand>();

int Gdb::maxPrintElements = 200;
bool Gdb::echo_on = false;

std::vector<int> Gdb::blocks = std::vector<int>();
int Gdb::inScript = 0;

bool Gdb::captureKilledThreads = false;
std::list<TaskInfo> Gdb::killedThreads = std::list<TaskInfo>();

int Gdb::shell_exitcode_id = -1;

HWND Gdb::gameWindow = NULL;
HWND Gdb::consoleWindow = NULL;
HHOOK Gdb::keyHook = NULL;
