#pragma once

#define DEBUGGER_XDEBUG

#include "ScriptLibraryR.h"
#include "debug.h"
#include "assembler.h"
#include "utils.h"
#include "base64.h"

#include <cstdlib>
#include <stdio.h>

#include <winsock2.h>
#include <WS2tcpip.h>

//Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#undef __FILENAME__
#undef LOG_LEVEL
#undef PAUSE_ON
#define __FILENAME__ "xdebug.h"
#define LOG_LEVEL 4
#define PAUSE_ON 0
#include "logger.h"

enum XDBG_ERR {
	NO_ERR = 0,
	PARSE_ERR_IN_CMD = 1,
	DUP_ARG_IN_CMD = 2,
	INVALID_OPTS = 3,
	UNIMPLEMENTED_METHOD = 4,
	CMD_NOT_AVAIL = 5,

	CANT_OPEN_FILE = 100,
	STREAM_REDIR_FAILED = 101,

	SET_BREAKPOINT_FAILED = 200,
	BREAKPOINT_TYPE_NOT_SUPPORTED = 201,
	INVALID_BREAKPOINT = 202,
	NO_CODE_ON_BP_LINE = 203,
	INVALID_BREAKPOINT_STATE = 204,
	NO_SUCH_BREAKPOINT = 205,
	ERR_EVAL_CODE = 206,
	INVALID_EXPR = 207,

	GET_PROP_FAILED = 300,
	INVALID_STACK_DEPTH = 301,
	INVALID_CONTEXT = 302,

	ENC_NOT_SUPPORTED = 900,
	INTERNAL_EXCEPTION = 998,
	UNKNOWN_ERR = 999
};

enum XDBG_STATUS {
	STARTING, STOPPING, STOPPED, RUNNING, BREAK
};

const char* XDBG_STATUS_STR[] = { "starting", "stopping", "stopped", "running", "break" };

namespace XDebugStatus {
	std::string message = "";

	std::string getMessage(std::string dflt) {
		std::string r = message != "" ? message : dflt;
		message = "";
		return r;
	}
};

namespace XDebugFormatter {
	static std::string formatLineBreakpoint(LineBreakpoint* breakpoint) {
		std::string item;
		std::string file = pathToUrl(findSourceFile(breakpoint->filename));
		if (breakpoint->getCondition() == NULL) {
			item =
				"<breakpoint id=\"" + std::to_string(breakpoint->getId()) + "\" "
				"type=\"line\" "
				"state=\"" + (breakpoint->isEnabled() ? "enabled" : "disabled") + "\" "
				"filename=\"" + file + "\" "
				"lineno=\"" + std::to_string(breakpoint->lineno) + "\" "
				"hit_value=\"" + std::to_string(breakpoint->targetHitCount) + "\" "
				"hit_condition=\">=\" "
				"hit_count=\"" + std::to_string(breakpoint->hits) + "\"/>";
		} else {
			item =
				"<breakpoint id=\"" + std::to_string(breakpoint->getId()) + "\" "
				"type=\"conditional\" "
				"state=\"" + (breakpoint->isEnabled() ? "enabled" : "disabled") + "\" "
				"filename=\"" + breakpoint->filename + "\" "
				"lineno=\"" + std::to_string(breakpoint->lineno) + "\" "
				"expression=\"" + breakpoint->getCondition()->str + "\" "
				"hit_value=\"" + std::to_string(breakpoint->targetHitCount) + "\" "
				"hit_condition=\">=\" "
				"hit_count=\"" + std::to_string(breakpoint->hits) + "\"/>";
		}
		return item;
	}

	static std::string formatWatch(Watch* watch) {
		std::string item =
			"<breakpoint id=\"" + std::to_string(watch->getId()) + "\" "
			"type=\"conditional\" "
			"state=\"" + (watch->isEnabled() ? "enabled" : "disabled") + "\" ";
		if (watch->task != NULL) {
			item += "function=\"" + std::string(watch->task->name) + "\" ";
		}
		item +=
			"expression=\"" + watch->getCondition()->str + "\"/>";
		return item;
	}

	static std::string formatCallCatchpoint(CallCatchpoint* catchpoint) {
		std::string item =
			"<breakpoint id=\"" + std::to_string(catchpoint->getId()) + "\" "
			"type=\"conditional\" "
			"state=\"" + (catchpoint->isEnabled() ? "enabled" : "disabled") + "\" "
			"function=\"" + catchpoint->getScript() + "\"/>";
		return item;
	}

	static std::string formatBreakpoint(Breakpoint* breakpoint) {
		if (breakpoint->getType() == BreakpointType::LINE) {
			return formatLineBreakpoint((LineBreakpoint*)breakpoint);
		} else if (breakpoint->getType() == BreakpointType::WATCH) {
			return formatWatch((Watch*)breakpoint);
		} else if (breakpoint->getType() == BreakpointType::CALL) {
			return formatCallCatchpoint((CallCatchpoint*)breakpoint);
		} else {
			ERR("unsupported breakpoint type %i", breakpoint->getType());
			return "";
		}
	}
}


class DebugThread {
private:
	static const int BUFFER_SIZE = 1024;
	static const int LARGE_BUF = 1024 * 32;
	static const int MAX_ARGS = 64;

	char recvbuf[BUFFER_SIZE] = {0};
	int recvlen = 0;

	std::string icode = "";

public:
	Task* thread = NULL;
	XDBG_STATUS status = XDBG_STATUS::RUNNING;
	SOCKET sock = INVALID_SOCKET;

	std::string runCmd = "";
	int runTrxId = -1;
	std::string breakData = "";

	int max_depth = 8;
	int max_children = 15;
	int max_data = 512;

	DebugThread() {}

	DebugThread(Task* task) {
		this->thread = task;
	}

	~DebugThread() {
		detach();
	}

	void detach() {
		if (sock != INVALID_SOCKET) {
			shutdown(sock, SD_SEND);
			closesocket(sock);
			sock = INVALID_SOCKET;
			INFO("detached from IDE");
		}
		if (status == XDBG_STATUS::BREAK) {
			status = XDBG_STATUS::RUNNING;
		}
	}

	void attach(sockaddr_in* addr, const char* ideKey, const char* cookie, const char* appid) {
		char buffer[BUFFER_SIZE];
		INFO("connecting to IDE...");
		if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
			ERR("socket creation failed with error: %i", WSAGetLastError());
		} else if (connect(sock, (sockaddr*)addr, sizeof(sockaddr_in)) < 0) {
			ERR("connection failed with error: %i", WSAGetLastError());
		} else {
			INFO("connected to IDE");
			int threadId = 0;
			std::string file;
			if (thread != NULL) {
				threadId = thread->taskNumber;
				file = findSourceFile(thread->filename);
				file = file != "" ? pathToUrl(file) : "dbgp:_asm";
			} else {
				file = "dbgp:_empty";
			}
			snprintf(buffer, BUFFER_SIZE,
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<init appid=\"BWCI_xdebug\" idekey=\"%s\" session=\"%s\" thread=\"%u\" parent=\"%s\" language=\"CHL\" "
				"protocol_version=\"1.0\" fileuri=\"%s\">\n"
				"	<engine version=\"1\"><![CDATA[BWCIXdebug]]></engine>\n"
				"	<author><![CDATA[Daniele Lombardi]]></author>\n"
				"	<license><![CDATA[GPL-3.0]]></license>\n"
				"	<url><![CDATA[https://github.com/Daniels118/BWCI_debugger]]></url>\n"
				"	<copyright><![CDATA[Copyright (c) 2024 - by Daniele Lombardi]]></copyright>\n"
				"</init>",
				ideKey, cookie, threadId, appid, file.c_str());
			usend(buffer);
			readAndExecCmds();
		}
	}

	bool hasIncomingCommands() {
		size_t cmdlen = strnlen(recvbuf, recvlen);
		if ((int)cmdlen < recvlen) return true;
		if (sock == INVALID_SOCKET) return false;
		const timeval zero = { 0, 0 };
		fd_set socks;
		socks.fd_count = 1;
		socks.fd_array[0] = this->sock;
		int r = select(0, &socks, NULL, NULL, &zero) > 0;
		if (r == SOCKET_ERROR) {
			ERR("select failed with error: %i", WSAGetLastError());
		}
		return r > 0;
	}

	void readAndExecCmds() {
		if (sock == INVALID_SOCKET) return;
		readAndExecCmd();
		while (sock != INVALID_SOCKET && (recvlen > 0 || status != XDBG_STATUS::RUNNING)) {
			readAndExecCmd();
		}
	}

	bool readAndExecCmd() {
		if (sock == INVALID_SOCKET) return false;
		size_t cmdlen = strnlen(recvbuf, recvlen);
		if (cmdlen == recvlen) {
			//TRACE("No commands in buffer, trying to receive more data...");
			if (!fill_recvbuf()) {
				ERR("Failed to read command");
				return false;
			}
			cmdlen = strnlen(recvbuf, recvlen);
			if (cmdlen == recvlen) {
				TRACE("No data available.");
				return false;	//No enough data available
			}
		}
		char buffer[BUFFER_SIZE];
		strcpy(buffer, recvbuf);
		memcpy(recvbuf, recvbuf + cmdlen + 1, recvlen - (cmdlen + 1));
		recvlen -= cmdlen + 1;
		execCmd(buffer);
		return true;
	}

	void send_response(const char* cmd, int trxId, std::string data, const char* attrfmt, ...) {
		char* buffer = (char*)malloc(LARGE_BUF);
		if (buffer == NULL) {
			ERR("failed to allocate buffer");
			return;
		}
		int n = snprintf(buffer, LARGE_BUF,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<response xmlns=\"urn:debugger_protocol_v1\" "
				"xmlns:xdebug=\"https://xdebug.org/dbgp/xdebug\" "
				"command=\"%s\" transaction_id=\"%i\" ",
			cmd, trxId);
		if (attrfmt != NULL) {
			va_list args;
			va_start(args, attrfmt);
			vsprintf(buffer + n, attrfmt, args);
			va_end(args);
		}
		if (data == "") {
			strcat(buffer, "/>");
		} else {
			strcat(buffer, ">");
			strcat(buffer, data.c_str());
			strcat(buffer, "</response>");
		}
		usend(buffer);
		free(buffer);
	}

	void send_stream(const char* type, const char* data) {
		char* buffer = (char*)malloc(LARGE_BUF);
		if (buffer == NULL) {
			ERR("failed to allocate buffer");
			return;
		}
		snprintf(buffer, BUFFER_SIZE,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<stream xmlns=\"urn:debugger_protocol_v1\" type=\"%s\" encoding=\"base64\"><![CDATA[",
			type);
		base64_encode(data, strlen(data), buffer + strlen(buffer), NULL);
		strcat(buffer, "]]></stream>");
		usend(buffer);
		free(buffer);
	}

	void notify(const char* customNs, const char* nsUri, const char* name, const char* customElement, const char* data) {
		char buffer[BUFFER_SIZE];
		if (customElement == NULL) customElement = "";
		snprintf(buffer, BUFFER_SIZE,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<notify xmlns=\"urn:debugger_protocol_v1\" "
			"xmlns:%s=\"%s\" name=\"%s\" encoding=\"base64\">%s<![CDATA[",
			customNs, nsUri, name, customElement);
		base64_encode(data, strlen(data), buffer + strlen(buffer), NULL);
		strcat(buffer, "]]></notify>");
		usend(buffer);
	}

	void send_error(const char* cmd, int trxId, XDBG_ERR code, std::string msg) {
		char* buffer = (char*)malloc(LARGE_BUF);
		if (buffer == NULL) {
			printf("failed to allocate buffer");
			return;
		}
		snprintf(buffer, BUFFER_SIZE,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<response xmlns=\"urn:debugger_protocol_v1\" xmlns:xdebug=\"http://xdebug.org/dbgp/xdebug\" "
					"command=\"%s\" transaction_id=\"%i\">\n"
			"	<error code=\"%i\"><message>%s</message></error>\n"
			"</response>",
			cmd, trxId, code, cdata(msg).c_str());
		usend(buffer);
		free(buffer);
	}

private:
	void execCmd(char* buffer) {
		DEBUG("executing: %s", buffer);
		char* argv[MAX_ARGS];
		int argc = splitArgs(buffer, ' ', argv, MAX_ARGS);
		char* cmd = argv[0];
		int trxId = atoi(getArgValOrDefault(argv, argc, "-i", "0"));
		if (streq(cmd, "status")) {
			send_response(cmd, trxId, "", "status=\"%s\" reason=\"ok\"", XDBG_STATUS_STR[status]);
		} else if (streq(cmd, "feature_get")) {
			c_feature_get(cmd, trxId, argv, argc);
		} else if (streq(cmd, "feature_set")) {
			c_feature_set(cmd, trxId, argv, argc);
		} else if (streq(cmd, "run")) {
			c_run(cmd, trxId, argv, argc);
		} else if (streq(cmd, "step_into")) {
			c_step_into(cmd, trxId, argv, argc);
		} else if (streq(cmd, "step_over")) {
			c_step_over(cmd, trxId, argv, argc);
		} else if (streq(cmd, "step_out")) {
			c_step_out(cmd, trxId, argv, argc);
		} else if (streq(cmd, "stop")) {
			c_stop(cmd, trxId, argv, argc);
		} else if (streq(cmd, "detach")) {
			c_detach(cmd, trxId, argv, argc);
		} else if (streq(cmd, "breakpoint_set")) {
			c_breakpoint_set(cmd, trxId, argv, argc);
		} else if (streq(cmd, "breakpoint_get")) {
			c_breakpoint_get(cmd, trxId, argv, argc);
		} else if (streq(cmd, "breakpoint_update")) {
			c_breakpoint_update(cmd, trxId, argv, argc);
		} else if (streq(cmd, "breakpoint_remove")) {
			c_breakpoint_remove(cmd, trxId, argv, argc);
		} else if (streq(cmd, "breakpoint_list")) {
			c_breakpoint_list(cmd, trxId, argv, argc);
		} else if (streq(cmd, "stack_depth")) {
			c_stack_depth(cmd, trxId, argv, argc);
		} else if (streq(cmd, "stack_get")) {
			c_stack_get(cmd, trxId, argv, argc);
		} else if (streq(cmd, "context_names")) {
			c_context_names(cmd, trxId, argv, argc);
		} else if (streq(cmd, "context_get")) {
			c_context_get(cmd, trxId, argv, argc);
		} else if (streq(cmd, "typemap_get")) {
			c_typemap_get(cmd, trxId, argv, argc);
		} else if (streq(cmd, "property_get")) {
			c_property_get(cmd, trxId, argv, argc);
		} else if (streq(cmd, "property_set")) {
			c_property_set(cmd, trxId, argv, argc);
		} else if (streq(cmd, "property_value")) {
			c_property_value(cmd, trxId, argv, argc);
		} else if (streq(cmd, "source")) {
			c_source(cmd, trxId, argv, argc);
		} else if (streq(cmd, "stdout")) {
			c_stdout(cmd, trxId, argv, argc);
		} else if (streq(cmd, "stderr")) {
			c_stderr(cmd, trxId, argv, argc);
		} else if (streq(cmd, "break")) {
			c_break(cmd, trxId, argv, argc);
		} else if (streq(cmd, "eval")) {
			c_eval(cmd, trxId, argv, argc);
		} else if (streq(cmd, "interact")) {
			c_interact(cmd, trxId, argv, argc);
		} else {
			send_error(cmd, trxId, CMD_NOT_AVAIL, "Command not available");
		}
	}

	void c_run(char* cmd, int trxId, char** argv, int argc) {
		runCmd = std::string(cmd);
		runTrxId = trxId;
		resumeThread(thread->taskNumber);
	}

	void c_step_into(char* cmd, int trxId, char** argv, int argc) {
		runCmd = std::string(cmd);
		runTrxId = trxId;
		breakFromAddress = 0x7FFFFFFF;
		breakAfterLines = 1;
		steppingThread = thread;
		stepInMaxDepth = 9999;
		resumeThread(thread->taskNumber);
	}

	void c_step_over(char* cmd, int trxId, char** argv, int argc) {
		runCmd = std::string(cmd);
		runTrxId = trxId;
		breakFromAddress = 0x7FFFFFFF;
		breakAfterLines = 1;
		steppingThread = thread;
		stepInMaxDepth = getFrameDepth(getInnermostFrame(thread));
		resumeThread(thread->taskNumber);
	}

	void c_step_out(char* cmd, int trxId, char** argv, int argc) {
		runCmd = std::string(cmd);
		runTrxId = trxId;
		breakFromAddress = 0x7FFFFFFF;
		breakAfterLines = 1;
		steppingThread = thread;
		stepInMaxDepth = getFrameDepth(getInnermostFrame(thread)) - 1;
		resumeThread(thread->taskNumber);
	}

	void c_stop(char* cmd, int trxId, char** argv, int argc) {
		status = XDBG_STATUS::STOPPED;
		send_response(cmd, trxId, "", "status=\"stopped\" reason=\"ok\"");
		detach();
	}

	void c_detach(char* cmd, int trxId, char** argv, int argc) {
		resumeThread(thread->taskNumber);
		send_response(cmd, trxId, "", "status=\"running\" reason=\"ok\"");
		detach();
	}

	void c_feature_get(char* cmd, int trxId, char** argv, int argc) {
		char* name = getArgVal(argv, argc, "-n");
		if (streq(name, "language_supports_threads")) {
			send_response(cmd, trxId, cdata("1"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "language_name")) {
			send_response(cmd, trxId, cdata("CHL"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "language_version")) {
			send_response(cmd, trxId, cdata("8"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "encoding")) {
			send_response(cmd, trxId, cdata("windows-1252"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "protocol_version")) {
			send_response(cmd, trxId, cdata("1"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "supports_async")) {
			send_response(cmd, trxId, cdata("1"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "data_encoding")) {
			send_response(cmd, trxId, cdata("base64"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "breakpoint_languages")) {
			send_response(cmd, trxId, cdata("CHL,ASM"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "breakpoint_types")) {
			//send_response(cmd, trxId, cdata("line call return exception conditional watch"), "feature_name=\"%s\" supported=\"1\"", name);
			send_response(cmd, trxId, cdata("line call exception conditional watch"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "multiple_sessions")) {
			send_response(cmd, trxId, cdata("0"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "max_children")) {
			send_response(cmd, trxId, cdata(std::to_string(max_children)), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "max_data")) {
			send_response(cmd, trxId, cdata(std::to_string(max_data)), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "max_depth")) {
			send_response(cmd, trxId, cdata(std::to_string(max_depth)), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "breakpoint_details")) {
			send_response(cmd, trxId, cdata("1"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "extended_properties")) {
			send_response(cmd, trxId, cdata("0"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "notify_ok")) {
			send_response(cmd, trxId, cdata("1"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "resolved_breakpoints")) {
			send_response(cmd, trxId, cdata("0"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "supported_encodings")) {
			send_response(cmd, trxId, cdata("windows-1252"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "supports_postmortem")) {
			send_response(cmd, trxId, cdata("0"), "feature_name=\"%s\" supported=\"1\"", name);
		} else if (streq(name, "show_hidden")) {
			send_response(cmd, trxId, cdata("0"), "feature_name=\"%s\" supported=\"1\"", name);
		} else {
			send_response(cmd, trxId, cdata("0"), "feature_name=\"%s\" supported=\"0\"", name);
		}
	}

	void c_feature_set(char* cmd, int trxId, char** argv, int argc) {
		char* name = getArgVal(argv, argc, "-n");
		char* sVal = getArgVal(argv, argc, "-v");
		if (streq(name, "max_depth")) {
			max_depth = atoi(sVal);
		} else if (streq(name, "max_children")) {
			max_children = atoi(sVal);
		} else if (streq(name, "max_data")) {
			max_data = atoi(sVal);
		} else if (streq(name, "")) {

		} else {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Unknown feature");
			return;
		}
		send_response(cmd, trxId, "", "feature=\"%s\" success=\"1\"", name);
	}

	void c_breakpoint_set(char* cmd, int trxId, char** argv, int argc) {
		char* type = getArgVal(argv, argc, "-t");
		if (type == NULL) {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Missing breakpoint type");
			return;
		}
		bool state = streq(getArgValOrDefault(argv, argc, "-s", "enabled"), "enabled");
		int lineno = atoi(getArgValOrDefault(argv, argc, "-n", "-1"));
		char* filename = getArgVal(argv, argc, "-f");
		char tmpName[MAX_PATH];
		int ip = -1;
		if (filename != NULL) {
			if (strncmp(filename, "file://", 7) == 0) {
				strcpy(tmpName, urlToPath(filename).c_str());
				filename = (char*)strrpbrk(tmpName, "/\\");
				if (filename != NULL) {
					filename++;	//Skip the directory separator
				} else {
					filename = tmpName;	//If no directory separator, then the filename is the whole path
				}
				DEBUG("breakpoint filename: %s", filename);
				ip = findInstructionIndex(filename, lineno);
			} else if (streq(filename, "dbgp:_asm")) {
				ip = lineno - 1;
			} else {
				ERR("Invalid filename: %s", filename);
				send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Invalid filename");
				return;
			}
		} else {
			filename = thread->filename;
			if (lineno >= 0) {
				ip = findInstructionIndex(filename, lineno);
			}
		}
		char* func = getArgVal(argv, argc, "-m");
		char* exception = getArgVal(argv, argc, "-x");
		int hitCount = atoi(getArgValOrDefault(argv, argc, "-h", "0"));
		char* hitCond = getArgValOrDefault(argv, argc, "-o", ">=");
		if (!streq(hitCond, ">=")) {
			ERR("hit condition not supported: %s", hitCond);
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Hit condition not supported");
			return;
		}
		bool temp = streq(getArgValOrDefault(argv, argc, "-r", "0"), "1");
		char* cond64 = getArgVal(argv, argc, "--");
		char cond[1024] = { 0 };
		if (cond64 != NULL) {
			base64_decode(cond64, strlen(cond64), cond, NULL);
			DEBUG("  with condition: %s", cond);
		}
		Breakpoint* breakpoint = NULL;
		if (streq(type, "line")) {
			breakpoint = getBreakpointAtLine(filename, lineno);
			if (breakpoint == NULL) {
				breakpoint = setLineBreakpoint(filename, lineno, ip, NULL, NULL);
			}
		} else if (streq(type, "call")) {
			breakpoint = getCallCatchpoint(func);
			if (breakpoint == NULL) {
				breakpoint = setCallCatchpoint(func);
			}
		} else if (streq(type, "return")) {
			send_error(cmd, trxId, XDBG_ERR::BREAKPOINT_TYPE_NOT_SUPPORTED, "Breakpoint type not supported");
		} else if (streq(type, "exception")) {
			send_error(cmd, trxId, XDBG_ERR::BREAKPOINT_TYPE_NOT_SUPPORTED, "Breakpoint type not supported");
		} else if (streq(type, "conditional")) {
			breakpoint = getBreakpointAtLine(filename, lineno);
			if (breakpoint == NULL) {
				breakpoint = setLineBreakpoint(filename, lineno, ip, NULL, cond);
			}
		} else if (streq(type, "watch")) {
			Task* frame = getInnermostFrame(thread);
			breakpoint = getWatchByExpression(frame, cond);
			if (breakpoint == NULL) {
				breakpoint = addWatch(frame, cond);
			}
		} else {
			send_error(cmd, trxId, XDBG_ERR::BREAKPOINT_TYPE_NOT_SUPPORTED, "Unknown breakpoint type");
			return;
		}
		if (breakpoint != NULL) {
			TRACE("breakpoint created");
			breakpoint->targetHitCount = hitCount;
			breakpoint->temporary = temp;
			send_response(cmd, trxId, "", "state=\"%s\" id=\"%i\"", breakpoint->isEnabled() ? "enabled" : "disabled", breakpoint->getId());
		} else {
			ERR("breakpoint creation failed");
			send_error(cmd, trxId, XDBG_ERR::SET_BREAKPOINT_FAILED, XDebugStatus::getMessage("Breakpoint creation failed"));
		}
	}

	void c_breakpoint_get(char* cmd, int trxId, char** argv, int argc) {
		int id = atoi(getArgVal(argv, argc, "-d"));
		Breakpoint* breakpoint = getBreakpointById(id);
		if (breakpoint != NULL) {
			std::string item = XDebugFormatter::formatBreakpoint(breakpoint);
			send_response(cmd, trxId, item.c_str(), NULL);
		} else {
			send_error(cmd, trxId, XDBG_ERR::NO_SUCH_BREAKPOINT, "Breakpoint not found");
		}
	}

	void c_breakpoint_update(char* cmd, int trxId, char** argv, int argc) {
		int id = atoi(getArgVal(argv, argc, "-d"));
		char* sState = getArgVal(argv, argc, "-s");
		char* sLineno = getArgVal(argv, argc, "-n");
		char* sHitValue = getArgVal(argv, argc, "-h");
		char* cond64 = getArgVal(argv, argc, "--");
		char cond[1024] = {0};
		Breakpoint* breakpoint = getBreakpointById(id);
		if (breakpoint != NULL) {
			if (breakpoint->getType() == BreakpointType::LINE) {
				if (sLineno != NULL && atoi(sLineno) != ((LineBreakpoint*)breakpoint)->lineno) {
					send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Changing line of existing breakpoint is not supported");
					return;
				}
			}
			if (sState != NULL) {
				breakpoint->setEnabled(streq(sState, "enabled"));
			}
			if (cond64 != NULL) {
				base64_decode(cond64, strlen(cond64), cond, NULL);
				Script* script = NULL;
				if (breakpoint->getType() == BreakpointType::LINE) {
					script = ((LineBreakpoint*)breakpoint)->script;
				} else if (breakpoint->getType() == BreakpointType::WATCH) {
					script = ((Watch*)breakpoint)->getCondition()->script;
				}
				Expression* expr = getCompiledExpression(script, cond, DT_BOOLEAN);
				if (expr != NULL) {
					breakpoint->setCondition(expr);
				} else {
					send_error(cmd, trxId, XDBG_ERR::INVALID_EXPR, XDebugStatus::getMessage("Invalid expression"));
					return;
				}
			}
			send_response(cmd, trxId, "", NULL);
		} else {
			send_error(cmd, trxId, XDBG_ERR::NO_SUCH_BREAKPOINT, "Breakpoint not found");
		}
	}

	void c_breakpoint_remove(char* cmd, int trxId, char** argv, int argc) {
		int id = atoi(getArgVal(argv, argc, "-d"));
		Breakpoint* breakpoint = getBreakpointById(id);
		if (breakpoint != NULL) {
			unsetBreakpoint(breakpoint);
			send_response(cmd, trxId, "", NULL);
		} else {
			send_error(cmd, trxId, XDBG_ERR::NO_SUCH_BREAKPOINT, "Breakpoint not found");
		}
	}

	void c_breakpoint_list(char* cmd, int trxId, char** argv, int argc) {
		auto breakpoints = getBreakpoints();
		std::string items;
		items.reserve(128 * (breakpoints.size() + 1));
		for (auto breakpoint : breakpoints) {
			items += "\n" + XDebugFormatter::formatBreakpoint(breakpoint);
		}
		send_response(cmd, trxId, items.c_str(), NULL);
	}

	void c_stack_depth(char* cmd, int trxId, char** argv, int argc) {
		int depth = getFrameDepth(getInnermostFrame(thread));
		send_response(cmd, trxId, "", "depth=\"%i\"", depth);
	}

	void c_stack_get(char* cmd, int trxId, char** argv, int argc) {
		char* sDepth = getArgVal(argv, argc, "-d");
		if (sDepth == NULL) {
			std::string items;
			items.reserve(8192);
			Task* frame = getInnermostFrame(thread);
			for (int depth = 0; frame != NULL; depth++) {
				items += "\n" + formatFrame(frame, depth);
				frame = getParentFrame(frame);
			}
			send_response(cmd, trxId, items.c_str(), NULL);
		} else {
			int depth = atoi(sDepth);
			Task* frame = getFrameAt(thread, depth);
			std::string item = formatFrame(frame, depth);
			send_response(cmd, trxId, item.c_str(), NULL);
		}
	}

	void c_context_names(char* cmd, int trxId, char** argv, int argc) {
		std::string items =
			"<context name=\"Local\" id=\"0\"/>\n"
			"<context name=\"Global\" id=\"1\"/>";
		send_response(cmd, trxId, items.c_str(), NULL);
	}

	void c_context_get(char* cmd, int trxId, char** argv, int argc) {
		int depth = atoi(getArgValOrDefault(argv, argc, "-d", "0"));
		int contextId = atoi(getArgValOrDefault(argv, argc, "-c", "0"));
		if (contextId == 0) {
			Task* frame = getFrameAt(thread, depth);
			if (frame == NULL) {
				send_error(cmd, trxId, XDBG_ERR::INVALID_STACK_DEPTH, "Invalid stack depth");
			} else {
				std::string items;
				items.reserve(8192);
				for (Var* var = frame->localVars.pFirst; var < frame->localVars.pEnd; var++) {
					if (var->name[0] != '_' && !streq(var->name, "LHVMA")) {
						std::string item = formatVar(frame, var, 0, NULL);
						items += "\n" + item;
					}
				}
				send_response(cmd, trxId, items.c_str(), "context=\"%i\"", contextId);
			}
		} else if (contextId == 1) {
			std::string items;
			items.reserve(8192);
			for (Var* var = ScriptLibraryR::globalVars->pFirst + 1; var < ScriptLibraryR::globalVars->pEnd; var++) {
				if (var->name[0] != '_' && !streq(var->name, "LHVMA")) {
					std::string item = formatVar(NULL, var, 0, NULL);
					items += "\n" + item;
				}
			}
			send_response(cmd, trxId, items.c_str(), "context=\"%i\"", contextId);
		} else {
			send_error(cmd, trxId, XDBG_ERR::INVALID_CONTEXT, "Invalid context id");
			return;
		}
	}

	void c_typemap_get(char* cmd, int trxId, char** argv, int argc) {
		std::string attr =
			"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
			"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"";
		std::string items = "";
			//"<map type=\"float\" name=\"float\" xsi:type=\"xsd:float\"/>"
		send_response(cmd, trxId, items.c_str(), attr.c_str());
	}

	void c_property_get(char* cmd, int trxId, char** argv, int argc) {
		int depth = atoi(getArgValOrDefault(argv, argc, "-d", "0"));
		int contextId = atoi(getArgValOrDefault(argv, argc, "-c", "0"));
		char* name = getArgVal(argv, argc, "-n");
		int maxDataSize = atoi(getArgValOrDefault(argv, argc, "-m", "0"));
		int page = atoi(getArgValOrDefault(argv, argc, "-p", "0"));
		int datatype = DT_AUTODETECT;
		if (contextId == 0) {
			Task* frame = getFrameAt(thread, depth);
			if (frame == NULL) {
				send_error(cmd, trxId, XDBG_ERR::INVALID_STACK_DEPTH, "Invalid stack depth");
			} else {
				Var* val = evalString(frame, name, datatype);
				if (val != NULL) {
					std::string item = formatVar(frame, val, page, name);
					send_response(cmd, trxId, item.c_str(), NULL);
				} else {
					send_error(cmd, trxId, XDBG_ERR::GET_PROP_FAILED, XDebugStatus::getMessage("Failed to evaluate expression"));
				}
			}
		} else if (contextId == 1) {
			Var* val = evalString(NULL, name, datatype);
			if (val != NULL) {
				std::string item = formatVar(NULL, val, page, name);
				send_response(cmd, trxId, item.c_str(), NULL);
			} else {
				send_error(cmd, trxId, XDBG_ERR::GET_PROP_FAILED, XDebugStatus::getMessage("Failed to evaluate expression"));
			}
		} else {
			send_error(cmd, trxId, XDBG_ERR::INVALID_CONTEXT, "Invalid context id");
		}
	}

	void c_property_set(char* cmd, int trxId, char** argv, int argc) {
		int depth = atoi(getArgValOrDefault(argv, argc, "-d", "0"));
		int contextId = atoi(getArgValOrDefault(argv, argc, "-c", "0"));
		char* name = getArgVal(argv, argc, "-n");
		char* sDatatype = getArgValOrDefault(argv, argc, "-t", "float");
		int dataLen = atoi(getArgValOrDefault(argv, argc, "-l", "-1"));
		char* val64 = getArgVal(argv, argc, "--");
		char sVal[1024] = {0};
		int datatype = DT_AUTODETECT;
		if (base64_decode(val64, strlen(val64), sVal, NULL)) {
			std::string expr = std::string(name) + " = " + std::string(sVal) + "\n0";
			DEBUG("executing '%s'", expr.c_str());
			if (contextId == 0) {
				Task* frame = getFrameAt(thread, depth);
				if (frame == NULL) {
					send_error(cmd, trxId, XDBG_ERR::INVALID_STACK_DEPTH, "Invalid stack depth");
				} else {
					Var* res = evalString(frame, expr, datatype);
					if (res != NULL) {
						send_response(cmd, trxId, "", "success=\"1\"");
					} else {
						send_error(cmd, trxId, XDBG_ERR::ERR_EVAL_CODE, XDebugStatus::getMessage("Failed to evaluate expression"));
					}
				}
			} else if (contextId == 1) {
				Var* res = evalString(NULL, expr, datatype);
				if (res != NULL) {
					send_response(cmd, trxId, "", "success=\"1\"");
				} else {
					send_error(cmd, trxId, XDBG_ERR::ERR_EVAL_CODE, XDebugStatus::getMessage("Failed to evaluate expression"));
				}
			} else {
				send_error(cmd, trxId, XDBG_ERR::INVALID_CONTEXT, "Invalid context id");
			}
		} else {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Failed to decode expression");
		}
	}

	void c_property_value(char* cmd, int trxId, char** argv, int argc) {
		c_property_get(cmd, trxId, argv, argc);
	}

	void c_source(char* cmd, int trxId, char** argv, int argc) {
		size_t start = atoi(getArgValOrDefault(argv, argc, "-b", "1"));
		size_t end = atoi(getArgValOrDefault(argv, argc, "-e", "0"));
		char* file = getArgVal(argv, argc, "-f");
		if (start < 1) {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Begin line must be greater than 0");
			return;
		} else if (file == NULL) {
			file = this->thread->filename;
		} else if (strncmp(file, "dbgp:", 5) == 0) {
			file += 5;
		} else {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Unsupported file URI protocol");
			return;
		}
		DEBUG("file: %s", file);
		PAUSE;
		auto lines = getSource(file);
		if (end == 0) {
			end = lines.size();
		} else if (end > lines.size()) {
			end = lines.size();
		}
		std::string code;
		if (!lines.empty()) {
			code.reserve((end - start + 1) * 128);
			size_t i = start - 1;
			code += lines[i];
			for (i++; i < end; i++) {
				code += "\n" + lines[i];
			}
		}
		send_response(cmd, trxId, cdata(code), "success=\"1\"");
	}

	void c_stdout(char* cmd, int trxId, char** argv, int argc) {
		char* mode = getArgValOrDefault(argv, argc, "-c", "0");
		if (streq(mode, "0")) {
			send_response(cmd, trxId, "", "success=\"1\"");
		} else if (streq(mode, "1")) {
			send_response(cmd, trxId, "", "success=\"0\"");
		} else if (streq(mode, "2")) {
			send_response(cmd, trxId, "", "success=\"0\"");
		} else {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Invalid mode");
		}
	}

	void c_stderr(char* cmd, int trxId, char** argv, int argc) {
		char* mode = getArgValOrDefault(argv, argc, "-c", "0");
		if (streq(mode, "0")) {
			send_response(cmd, trxId, "", "success=\"1\"");
		} else if (streq(mode, "1")) {
			send_response(cmd, trxId, "", "success=\"0\"");
		} else if (streq(mode, "2")) {
			send_response(cmd, trxId, "", "success=\"0\"");
		} else {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Invalid mode");
		}
	}

	void c_break(char* cmd, int trxId, char** argv, int argc) {
		suspendThread(thread->taskNumber);
		send_response(cmd, trxId, "", "success=\"1\"");
	}

	void c_eval(char* cmd, int trxId, char** argv, int argc) {
		int page = atoi(getArgValOrDefault(argv, argc, "-p", "0"));
		int depth = atoi(getArgValOrDefault(argv, argc, "-d", "0"));
		char* expr64 = getArgVal(argv, argc, "--");
		if (expr64 != NULL) {
			char expression[2048] = {0};
			if (base64_decode(expr64, strlen(expr64), expression, NULL)) {
				DEBUG("evaluating \"%s\"...", expression);
				Task* frame = getFrameAt(thread, depth);
				int datatype = DT_AUTODETECT;
				Var* result = evalString(frame, expression, datatype);
				if (result != NULL) {
					DEBUG("\"%s\" evaluated successfully", expression);
					std::string item = formatVar(frame, result, page, expression);
					send_response(cmd, trxId, item, "success=\"1\"");
				} else {
					ERR("evaluation of \"%s\" failed", expression);
					send_error(cmd, trxId, XDBG_ERR::ERR_EVAL_CODE, XDebugStatus::getMessage("Failed to evaluate expression"));
				}
			} else {
				send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Failed to decode expression");
			}
		} else {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Expression missing");
		}
	}

	void c_interact(char* cmd, int trxId, char** argv, int argc) {
		char* mode = getArgValOrDefault(argv, argc, "-m", "");
		char* line64 = getArgVal(argv, argc, "--");
		char line[1024];
		if (streq(mode, "0") || streq(mode, "zero")) {
			icode = "";
			send_response(cmd, trxId, "", "status=\"%s\" more=\"1\" prompt=\">\"", XDBG_STATUS_STR[this->status]);
		} else if (line64 == NULL) {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Expression missing");
		} else if (base64_decode(line64, strlen(line64), line, NULL)) {
			if (streq(line, ".")) {
				Task* frame = getInnermostFrame(thread);
				int datatype = DT_AUTODETECT;
				Var* val = evalString(frame, icode, datatype);
				icode = "";
				if (val != NULL) {
					send_response(cmd, trxId, "", "status=\"interactive\" more=\"0\" prompt=\">\"");
					char data[1024] = {0};
					if (val->type == DT_FLOAT) {
						sprintf(data, "%f\n", val->floatVal);
					} else if (val->type == DT_INT) {
						sprintf(data, "%i\n", val->intVal);
					} else if (val->type == DT_BOOLEAN) {
						sprintf(data, "%s\n", val->intVal ? "true" : "false");
					} else if (val->type == DT_COORDS) {
						sprintf(data, "{%f, %f, %f}\n", val[0].floatVal, val[1].floatVal, val[2].floatVal);
					} else if (val->type == DT_OBJECT) {
						sprintf(data, "(object)%i\n", val->uintVal);
					}
					send_stream("stdout", data);
				} else {
					send_error(cmd, trxId, XDBG_ERR::ERR_EVAL_CODE, XDebugStatus::getMessage("Failed to evaluate expression"));
				}
			} else {
				if (!icode.empty()) icode += "\n";
				icode += line;
				send_response(cmd, trxId, "", "status=\"interactive\" more=\"1\" prompt=\">\"");
			}
		} else {
			send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS, "Failed to decode expression");
		}
	}

	std::string formatVar(Task* frame, Var* var, int page, const char* newName) {
		//TRACE("formatting var %s", var->name);
		bool arr = varIsArray(frame, var);
		if (arr) {
			int numChildren = getVarSize(frame, var);
			std::string name = std::string(newName == NULL ? var->name : newName);
			std::string item;
			item.reserve(128 * (min(numChildren, max_children) + 1));
			item +=
				"<property name=\""+name+"\" fullname=\""+name+"\" type=\"array\" constant=\"0\" children=\"1\" "
				"page=\""+std::to_string(page)+"\" "
				"pagesize=\""+std::to_string(max_children)+"\" "
				"numchildren=\"" + std::to_string(numChildren) + "\">";
			int start = page * max_children;
			int end = min(numChildren, start + max_children);
			for (int i = start; i < end; i++) {
				std::string sIndex = std::to_string(i);
				item += "\n\t" + formatAtomicVar(frame, var + i, sIndex, name+"["+sIndex+"]");
			}
			item += "\n</property>";
			return item;
		} else {
			return formatAtomicVar(frame, var, var->name, var->name);
		}
	}

	static std::string formatAtomicVar(Task* frame, Var* var, std::string name, std::string fullname) {
		//TRACE("formatting var %s", var->name);
		bool isValidObject = var->type == DataTypes::DT_OBJECT && var->uintVal != 0;
		bool children = false;
		int numChildren = 0;
		std::string type;
		std::string value;
		std::string item;
		item.reserve(isValidObject ? 1024 : 128);
		item +=
			"<property name=\"" + name + "\" fullname=\"" + fullname + "\" ";
		if (var->type == DataTypes::DT_OBJECT) {
			if (var->uintVal != 0) {
				type = "object";
				value = std::to_string(var->uintVal);
				children = true;
				int type = getObjectType(var->uintVal);
				int subtype = getObjectSubType(var->uintVal);
				std::string sType = getTypeName(type);
				std::string cls = strSnakeToCamel(strReplace(sType, "SCRIPT_OBJECT_TYPE_", ""));
				if (subtype != 9999) {
					std::string prefix = ObjectTypes::subtypesMap[sType] + "_";
					cls += "::" + strSnakeToCamel(strReplace(getSubTypeName(type, subtype), prefix, ""));
				}
				item += "classname=\"" + cls + "\" ";
			} else {
				type = "null";
				value = "null";
			}
		} else {
			type = "float";
			value = std::to_string(var->floatVal);
		}
		item += "type=\"" + type + "\" "
			"constant=\"0\" "
			"children=\"" + std::string(children ? "1" : "0") + "\" "
			"size=\"" + std::to_string(value.length()) + "\" ";
		if (var->type == DataTypes::DT_OBJECT && var->uintVal != 0) {
			std::string properties = formatObjectProperties(fullname, var->uintVal, &numChildren);
			item += "numchildren=\""+std::to_string(numChildren)+"\" page=\"0\">" + properties + "\n</property>";
		} else {
			item += ">" + cdata(value) + "</property>";
		}
		return item;
	}

	static std::string formatObjectProperties(std::string fullname, DWORD objId, int* numChildrenOut) {
		std::string items = "";
		int type = getObjectType(objId);
		const char* typeName = getTypeName(type);
		int subtype = getObjectSubType(objId);
		items += "\n\t" + formatInt("type", fullname + ".type", type);
		items += "\n\t" + formatInt("subtype", fullname + ".subtype", subtype);
		int n = 2;
		bool isCreature = type == ScriptObjectTypes["SCRIPT_OBJECT_TYPE_CREATURE"]
						|| type == ScriptObjectTypes["SCRIPT_OBJECT_TYPE_DUMB_CREATURE"]
						|| type == ScriptObjectTypes["SCRIPT_OBJECT_TYPE_FEMALE_CREATURE"];
		Var var;
		if (ObjectTypes::TypeProperties.contains(typeName)) {
			auto& propNames = ObjectTypes::TypeProperties[typeName];
			for (auto& propName : propNames) {
				int propVal = ObjectProperties[propName];
				std::string name = strSnakeToCamel(strReplace(propName, "SCRIPT_OBJECT_PROPERTY_TYPE_", ""));
				getObjectProperty(objId, propVal, &var);
				if (var.type == DT_FLOAT) {
					items += "\n\t" + formatFloat(name, propName + " of " + fullname, var.floatVal);
				} else if (var.type == DT_BOOLEAN) {
					items += "\n\t" + formatBool(name, propName + " of " + fullname, var.intVal);
				} else {	//INT and other types
					items += "\n\t" + formatInt(name, propName + " of " + fullname, var.intVal);
				}
				n++;
			}
		} else {
			for (auto entry : ObjectProperties) {
				std::string propName = entry.first;
				if (isCreature || !propName.starts_with("SCRIPT_OBJECT_PROPERTY_TYPE_CREATURE_")) {
					std::string name = strSnakeToCamel(strReplace(propName, "SCRIPT_OBJECT_PROPERTY_TYPE_", ""));
					getObjectProperty(objId, entry.second, &var);
					if (var.type == DT_FLOAT) {
						items += "\n\t" + formatFloat(name, propName + " of " + fullname, var.floatVal);
					} else if (var.type == DT_BOOLEAN) {
						items += "\n\t" + formatBool(name, propName + " of " + fullname, var.intVal);
					} else {	//INT and other types
						items += "\n\t" + formatInt(name, propName + " of " + fullname, var.intVal);
					}
					n++;
				}
			}
		}
		*numChildrenOut = n;
		return items;
	}

	static std::string formatFloat(std::string name, std::string fullname, float val) {
		std::string sVal = std::to_string(val);
		std::string item =
			"<property name=\""+name+"\" fullname=\""+fullname+"\" type=\"float\" children=\"0\" "
				"size=\""+std::to_string(sVal.length())+"\">"
			+ cdata(sVal) +
			"</property>";
		return item;
	}

	static std::string formatInt(std::string name, std::string fullname, int val) {
		std::string sVal = std::to_string(val);
		std::string item =
			"<property name=\"" + name + "\" fullname=\"" + fullname + "\" type=\"int\" children=\"0\" "
			"size=\"" + std::to_string(sVal.length()) + "\">"
			+ cdata(sVal) +
			"</property>";
		return item;
	}

	static std::string formatBool(std::string name, std::string fullname, bool val) {
		std::string sVal = val ? "1" : "0";
		std::string item =
			"<property name=\"" + name + "\" fullname=\"" + fullname + "\" type=\"bool\" children=\"0\" "
			"size=\"" + std::to_string(sVal.length()) + "\">"
			+ cdata(sVal) +
			"</property>";
		return item;
	}

	static std::string formatFrame(Task* frame, int level) {
		TaskInfo* info = getTaskInfo(frame);
		std::string file = pathToUrl(findSourceFile(frame->filename));
		std::string item =
			"<stack level=\"" + std::to_string(level) + "\" "
			"type=\"file\" "
			"filename=\"" + file + "\" "
			"lineno=\"" + std::to_string(getInstruction(info->currentIp)->linenumber) + "\" "
			"where=\"" + frame->name + "\"/>";
		return item;
	}

	bool fill_recvbuf() {
		if (sock == INVALID_SOCKET) return false;
		//TRACE("recv... ");
		int n = recv(sock, recvbuf, BUFFER_SIZE - recvlen, 0);
		if (n > 0) {
			//TRACE("%i bytes received", n);
			recvlen += n;
			return true;
		} else /*if (n == SOCKET_ERROR)*/ {
			ERR("failed with error: %i", WSAGetLastError());
			detach();
		}
		return false;
	}

	bool usend(const char* msg) {
		if (sock == INVALID_SOCKET) return false;
		size_t msglen = strlen(msg);
		char* buffer = (char*)malloc(msglen + 32);
		if (buffer == NULL) {
			ERR("failed to allocate buffer");
			return false;
		}
		_itoa(msglen, buffer, 10);
		size_t buflen = strlen(buffer) + 1;
		strcpy(buffer + buflen, msg);
		buflen += msglen + 1;
		TRACE("Sending:\n%s\n", msg);
		int n = send(sock, buffer, buflen, 0) == buflen;
		free(buffer);
		if (n == SOCKET_ERROR) {
			ERR("send failed with error: %i", WSAGetLastError());
			detach();
		}
		return n;
	}

	static std::string cdata(std::string str) {
		return "<![CDATA[" + str + "]]>";
	}
};


class XDebug : public Debugger {
private:
	static const int BUFFER_SIZE = 1024;
	static const int MAX_ARGS = 64;

	static int port;
	static sockaddr_in addr;

	static const char* ideKey;
	static const char* cookie;
	static const char* appid;

	static std::unordered_map<int, DebugThread> debugThreads;

	static volatile bool running;
	static volatile bool incomingCommands;

public:
	void init() {
		char buffer[BUFFER_SIZE];
		char* argv[MAX_ARGS];
		char* cmd = GetCommandLineA();
		strcpy(buffer, cmd);
		int argc = splitArgs(buffer, ' ', argv, MAX_ARGS);
		char* sPort = getArgVal(argv, argc, "/xdebug:port");
		if (sPort != NULL) {
			port = atoi(sPort);
			if (port <= 0) port = 9003;
		}
		//
		ideKey = getenv("DBGP_IDEKEY");
		if (ideKey == NULL) ideKey = "";
		cookie = getenv("DBGP_COOKIE");
		if (cookie == NULL) cookie = "BWCI";
		appid = getenv("APPID");
		if (appid == NULL) appid = "";
		//
		WSADATA wsaData = { 0 };
		int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) {
			ERR("WSAStartup failed: %i", iResult);
		} else {
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			InetPton(AF_INET, "127.0.0.1", &addr.sin_addr.s_addr);
		}
		//
		printf("WARNING: XDebug is an experimental feature\n");
		printf("Debugging with XDebug on port %i\n", port);
	}

	void term() {
		running = false;
		debugThreads.clear();
		WSACleanup();
	}

	void start() {
		debugThreads.clear();
		breakFromAddress = 0x7FFFFFFF;
	}

	void threadStarted(Task* task) {
		DEBUG("thread %i started", task->taskNumber);
		debugThreads[task->taskNumber] = DebugThread(task);
		DebugThread* dbgThread = &debugThreads[task->taskNumber];
		dbgThread->attach(&addr, ideKey, cookie, appid);
	}

	void threadRestored(Task* task) {
		DEBUG("thread %i restored", task->taskNumber);
		debugThreads[task->taskNumber] = DebugThread(task);
		DebugThread* dbgThread = &debugThreads[task->taskNumber];
		dbgThread->attach(&addr, ideKey, cookie, appid);
	}

	void threadPaused(Task* thread) {
		DEBUG("thread %i paused", thread->taskNumber);
		DebugThread* dbgThread = &debugThreads[thread->taskNumber];
		dbgThread->status = XDBG_STATUS::BREAK;
		dbgThread->send_response(dbgThread->runCmd.c_str(), dbgThread->runTrxId, dbgThread->breakData.c_str(), "status=\"break\" reason=\"ok\"");
		dbgThread->runTrxId = -1;
		dbgThread->breakData = "";
	}

	void taskPoll(Task* task) {
		Task* thread = getThread(task);
		DebugThread* dbgThread = &debugThreads[thread->taskNumber];
		while (dbgThread->hasIncomingCommands()) {
			TRACE("incoming async command for thread %i", thread->taskNumber);
			dbgThread->readAndExecCmd();
		}
		if (dbgThread->status == XDBG_STATUS::STOPPED) {
			stopThread(thread);
		}
	}

	void threadResumed(Task* thread) {
		DEBUG("thread %i resumed", thread->taskNumber);
		DebugThread* dbgThread = &debugThreads[thread->taskNumber];
		dbgThread->status = XDBG_STATUS::RUNNING;
	}

	void threadEnded(void* pThread, TaskInfo* info) {
		DEBUG("thread %i ended", info->id);
		if (debugThreads.contains(info->id)) {
			debugThreads[info->id].detach();
			debugThreads.erase(info->id);
		}
	}

	void onBreakpoint(Task* task, LineBreakpoint* breakpoint) {
		Task* thread = getThread(task);
		DebugThread* dbgThread = &debugThreads[thread->taskNumber];
		dbgThread->status = XDBG_STATUS::BREAK;
		std::string file = findSourceFile(task->filename);
		int lineno;
		if (file != "") {
			file = pathToUrl(file);
			lineno = getCurrentInstruction(task)->linenumber;
		} else {
			file = "dbgp:_asm";
			lineno = task->ip + 1;
		}
		DEBUG("thread %i hit breakpoint at %s:%i", thread->taskNumber, file.c_str(), lineno);
		dbgThread->breakData = XDebugFormatter::formatBreakpoint(breakpoint);
		suspendThread(thread->taskNumber);
	}

	void onCatchpoint(Task* task, Breakpoint* catchpoints[], size_t count) {
		Breakpoint* breakpoint = catchpoints[0];
		Task* thread = getThread(task);
		DebugThread* dbgThread = &debugThreads[thread->taskNumber];
		dbgThread->status = XDBG_STATUS::BREAK;
		std::string file = findSourceFile(task->filename);
		int lineno;
		if (file != "") {
			file = pathToUrl(file);
			lineno = getCurrentInstruction(task)->linenumber;
		} else {
			file = "dbgp:_asm";
			lineno = task->ip + 1;
		}
		DEBUG("thread %i hit catchpoint at %s:%i", thread->taskNumber, file.c_str(), lineno);
		dbgThread->breakData = XDebugFormatter::formatBreakpoint(breakpoint);
		suspendThread(thread->taskNumber);
	}

	void beforeInstruction(Task* task) {
		
	}

	void beforeLine(Task* task) {

	}

	void onPauseBeforeInstruction(Task* task) {

	}

	void onPauseBeforeLine(Task* task) {
		Task* thread = getThread(task);
		DebugThread* dbgThread = &debugThreads[thread->taskNumber];
		dbgThread->status = XDBG_STATUS::BREAK;
		std::string file = findSourceFile(task->filename);
		int lineno;
		if (file != "") {
			file = pathToUrl(file);
			lineno = getCurrentInstruction(task)->linenumber;
		} else {
			file = "dbgp:_asm";
			lineno = task->ip + 1;
		}
		dbgThread->breakData = "<xdebug:message filename=\"" + file + "\" lineno=\"" + std::to_string(lineno) + "\"/>";
		suspendThread(thread->taskNumber);
	}

	void onMessage(DWORD severity, const char* format, ...) {
		char buffer[2048] = {0};
		va_list args;
		va_start(args, format);
		vsnprintf(buffer, 2048, format, args);
		XDebugStatus::message = std::string(buffer);
		printf("%s\n", buffer);
		va_end(args);
	}

private:
	static DebugThread* getThreadWithIncomingCommands() {
		const timeval zero = { 0, 0 };
		fd_set socks;
		socks.fd_count = 1;
		for (auto& entry : debugThreads) {
			socks.fd_array[0] = entry.second.sock;
			int n = select(0, &socks, NULL, NULL, &zero);
			if (n > 0) {
				return &entry.second;
			}
		}
		return NULL;
	}
};

int XDebug::port = 9003;
sockaddr_in XDebug::addr = {0};
const char* XDebug::ideKey = NULL;
const char* XDebug::cookie = NULL;
const char* XDebug::appid = NULL;
std::unordered_map<int, DebugThread> XDebug::debugThreads = std::unordered_map<int, DebugThread>();
volatile bool XDebug::running = true;
volatile bool XDebug::incomingCommands = false;
