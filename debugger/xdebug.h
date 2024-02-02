#pragma once

#define DEBUGGER_XDEBUG

#include "ScriptLibraryR.h"
#include "debug.h"
#include "assembler.h"
#include "utils.h"
#include "base64.h"

#include <cstdlib>
#include <WS2tcpip.h>

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

const char* XDBG_STATUS_STR[] = {"starting", "stopping", "stopped", "running", "break"};

class Client {
	private:
		static const int BUFFER_SIZE = 1024;

		SOCKET sock = INVALID_SOCKET;
		char recvbuf[BUFFER_SIZE];
		int recvlen = 0;

		XDBG_STATUS status = STARTING;

	public:
		Task* thread;

		Client(Task* thread, sockaddr_in* addr) {
			this->thread = thread;
			char buffer[BUFFER_SIZE];
			if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
				printf("Socket creation error\n");
			} else if (inet_pton(AF_INET, "127.0.0.1", &addr->sin_addr) <= 0) {
				printf("Invalid address\n");
			} else if (connect(sock, (sockaddr*)addr, sizeof(sockaddr_in)) < 0) {
				printf("Connection failed\n");
			} else {
				printf("Connected\n");
				const char* ideKey = getenv("DBGP_IDEKEY");
				if (ideKey == NULL) ideKey = "";
				const char* cookie = getenv("DBGP_COOKIE");
				if (cookie == NULL) cookie = "";
				const char* appid = getenv("APPID");
				if (appid == NULL) appid = "";
				std::string file = strReplace(findSourceFile(thread->filename), "\\", "/");
				snprintf(buffer, BUFFER_SIZE,
					"<init appid=\"BWCI_xdebug\" idekey=\"%s\" session=\"%s\" thread=\"%u\" parent=\"%s\" language=\"CHL\" "
						"protocol_version=\"1.0\" fileuri=\"file:///%s\">"
						"<engine version=\"1\">product title</engine>"
						"<author>Daniele Lombardi</author>"
						"<license>GPL-3.0</license>"
						"<url>https://github.com/Daniels118/BWCI_debugger</url>"
						"<copyright>2024 - Daniele Lombardi</copyright>"
					"</init>",
					ideKey, cookie, thread->taskNumber, appid, file.c_str());
				int r = send(sock, buffer, strlen(buffer), 0);
				if (r == SOCKET_ERROR) {
					printf("send failed with error: %d\n", WSAGetLastError());
				}
			}
		}

		~Client() {
			if (sock != INVALID_SOCKET) {
				shutdown(sock, SD_SEND);
				closesocket(sock);
				sock = INVALID_SOCKET;
			}
		}

		void readAndExecCmds() {
			while (true) {
				readAndExecCmd();
			}
		}

		void readAndExecCmd() {
			size_t cmdlen = strnlen(recvbuf, recvlen);
			while (cmdlen == recvlen) {
				if (!fill_recvbuf()) {
					printf("Failed to read command\n");
					return;
				}
				cmdlen = strnlen(recvbuf, recvlen);
			}
			char buffer[BUFFER_SIZE];
			strcpy(buffer, recvbuf);
			memcpy(recvbuf, recvbuf + cmdlen + 1, recvlen - (cmdlen + 1));
			recvlen -= cmdlen + 1;
			execCmd(buffer);
		}

		void send_response(const char* cmd, int trxId, const char* data, const char* attrfmt, ...) {
			char buffer[BUFFER_SIZE];
			int n = snprintf(buffer, BUFFER_SIZE,
				"<?xml version=\"1.0\"encoding=\"UTF-8\"?>"
				"<response xmlns=\"urn:debugger_protocol_v1\" command=\"%s\" transaction_id=\"%i\" ",
				cmd, trxId);
			if (attrfmt != NULL) {
				va_list args;
				va_start(args, attrfmt);
				vsprintf(buffer + n, attrfmt, args);
				va_end(args);
			}
			if (data == NULL) {
				strcat(buffer, "/>");
			} else {
				strcat(buffer, ">");
				strcat(buffer, data);
				strcat(buffer, "</response>");
			}
			usend(buffer);
		}

		void send_stream(const char* type, const char* data) {
			char buffer[BUFFER_SIZE];
			snprintf(buffer, BUFFER_SIZE,
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				"<stream xmlns=\"urn:debugger_protocol_v1\" type=\"%s\" encoding=\"base64\">",
				type);
			base64_encode(data, strlen(data), buffer + strlen(buffer), NULL);
			strcat(buffer, "</stream>");
			usend(buffer);
		}

		void notify(const char* customNs, const char* nsUri, const char* name, const char* customElement, const char* data) {
			char buffer[BUFFER_SIZE];
			snprintf(buffer, BUFFER_SIZE,
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				"<notify xmlns=\"urn:debugger_protocol_v1\" "
						"xmlns:%s=\"%s\" name=\"%s\" encoding=\"base64\">%s",
				customNs, nsUri, name, customElement);
			base64_encode(data, strlen(data), buffer + strlen(buffer), NULL);
			strcat(buffer, "</notify>");
			usend(buffer);
		}

		void send_error(const char* cmd, int trxId, XDBG_ERR code) {
			char buffer[BUFFER_SIZE];
			snprintf(buffer, BUFFER_SIZE,
				"<?xml version=\"1.0\"encoding=\"UTF-8\"?>"
				"<response xmlns=\"urn:debugger_protocol_v1\" command=\"%s\" transaction_id=\"%i\">"
					"<error code=\"%i\"/>"
				"</response>",
				cmd, trxId, code);
			usend(buffer);
		}

	private:
		void execCmd(char* buffer) {
			char* argv[32];
			int argc = splitArgs(buffer, ' ', argv, 32);
			char* cmd = argv[0];
			int trxId = atoi(getArgValOrDefault(argv, argc, "-i", "0"));
			if (streq(cmd, "status")) {
				send_response(cmd, trxId, NULL, "status=\"%s\" reason=\"ok\"", XDBG_STATUS_STR[status]);
			} else if (streq(cmd, "feature_get")) {
				c_feature_get(cmd, trxId, argv, argc);
			} else if (streq(cmd, "feature_set")) {
				c_feature_set(cmd, trxId, argv, argc);
			} else if (streq(cmd, "run")) {
				
			} else if (streq(cmd, "step_into")) {

			} else if (streq(cmd, "step_over")) {

			} else if (streq(cmd, "step_out")) {

			} else if (streq(cmd, "stop")) {

			} else if (streq(cmd, "detach")) {

			} else if (streq(cmd, "breakpoint_set")) {

			} else if (streq(cmd, "breakpoint_get")) {

			} else if (streq(cmd, "breakpoint_update")) {

			} else if (streq(cmd, "breakpoint_remove")) {

			} else if (streq(cmd, "breakpoint_list")) {

			} else if (streq(cmd, "stack_depth")) {

			} else if (streq(cmd, "stack_get")) {

			} else if (streq(cmd, "context_names")) {

			} else if (streq(cmd, "context_get")) {

			} else if (streq(cmd, "typemap_get")) {

			} else if (streq(cmd, "property_get")) {

			} else if (streq(cmd, "property_set")) {

			} else if (streq(cmd, "property_value")) {

			} else if (streq(cmd, "source")) {

			} else if (streq(cmd, "stdout")) {

			} else if (streq(cmd, "stderr")) {

			} else if (streq(cmd, "break")) {

			} else if (streq(cmd, "eval")) {

			} else if (streq(cmd, "interact")) {

			} else {
				send_error(cmd, trxId, CMD_NOT_AVAIL);
			}
		}

		void c_feature_get(char* cmd, int trxId, char** argv, int argc) {
			char* name = getArgVal(argv, argc, "-n");
			if (streq(name, "language_supports_threads")) {
				send_response(cmd, trxId, "1", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "language_name")) {
				send_response(cmd, trxId, "CHL", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "language_version")) {
				send_response(cmd, trxId, "8", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "encoding")) {
				send_response(cmd, trxId, "windows-1252", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "protocol_version")) {
				send_response(cmd, trxId, "1", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "data_encoding")) {
				send_response(cmd, trxId, "base64", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "breakpoint_languages")) {
				send_response(cmd, trxId, "CHL", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "breakpoint_types")) {
				send_response(cmd, trxId, "line call return exception conditional watch", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "multiple_sessions")) {
				send_response(cmd, trxId, "1", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "max_children")) {
				send_response(cmd, trxId, "100", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "max_data")) {
				send_response(cmd, trxId, "256", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "max_depth")) {
				send_response(cmd, trxId, "3", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "breakpoint_details")) {
				send_response(cmd, trxId, "1", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "extended_properties")) {
				send_response(cmd, trxId, "0", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "notify_ok")) {
				send_response(cmd, trxId, "1", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "resolved_breakpoints")) {
				send_response(cmd, trxId, "0", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "supported_encodings")) {
				send_response(cmd, trxId, "windows-1252", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "supports_postmortem")) {
				send_response(cmd, trxId, "0", "feature_name=\"%s\" supported=\"1\"", name);
			} else if (streq(name, "show_hidden")) {
				send_response(cmd, trxId, "0", "feature_name=\"%s\" supported=\"1\"", name);
			} else {
				send_response(cmd, trxId, "0", "feature_name=\"%s\" supported=\"0\"", name);
			}
		}

		void c_feature_set(char* cmd, int trxId, char** argv, int argc) {
			char* name = getArgVal(argv, argc, "-n");
			char* sVal = getArgVal(argv, argc, "-v");
			if (streq(name, "")) {

			} else if (streq(name, "")) {

			} else {
				send_error(cmd, trxId, XDBG_ERR::INVALID_OPTS);
			}
		}

		bool fill_recvbuf() {
			int n = recv(sock, recvbuf, BUFFER_SIZE - recvlen, 0);
			if (n > 0) {
				recvlen += n;
				return true;
			}
			return false;
		}

		bool usend(const char* msg) {
			char buffer[BUFFER_SIZE];
			size_t msglen = strlen(msg);
			itoa(msglen, buffer, 10);
			size_t buflen = strlen(buffer) + 1;
			strcpy(buffer + buflen, msg);
			buflen += msglen + 1;
			return send(sock, buffer, buflen, 0) == buflen;
		}
};


class XDebug : public Debugger {
	private:
		static const int BUFFER_SIZE = 1024;
		static const int MAX_ARGS = 64;

		static char buffer[BUFFER_SIZE];
		static char* argv[MAX_ARGS];

		static int port;
		sockaddr_in addr;

		static std::unordered_map<int, Client> clients;

	public:
		void init() {
			#ifdef CHL_ASSEMBLER
				assembler_init();
			#endif
			char* cmd = GetCommandLineA();
			strcpy(buffer, cmd);
			int argc = splitArgs(buffer, ' ', argv, MAX_ARGS);
			char* sPort = getArgVal(argv, argc, "/xdebug:port");
			if (sPort != NULL) {
				port = atoi(sPort);
				if (port <= 0) port = 9000;
			}
			//
			WSADATA wsaData = {0};
			int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
			if (iResult != 0) {
				printf("WSAStartup failed: %d\n", iResult);
			} else {
				addr.sin_family = AF_INET;
				addr.sin_port = htons(port);
			}
		}

		void term() {
			clients.clear();
			WSACleanup();
		}

		void start() {

		}

		void threadStarted(Task* thread) {
			clients[thread->taskNumber] = Client(thread, &addr);
		}

		void threadResumed(Task* thread) {
			clients[thread->taskNumber] = Client(thread, &addr);
		}

		void threadEnded(void* pThread, TaskInfo* info) {
			clients.erase(info->id);
		}

		void breakpointHit(Task* task, Breakpoint* breakpoint) {

		}

		void onCatchpoint(Task* task, int event) {

		}

		void beforeInstruction(Task* task) {

		}

		void beforeLine(Task* task) {

		}

		void onPauseBeforeInstruction(Task* task) {

		}

		void onPauseBeforeLine(Task* task) {

		}

		void onException(Task* task, bool exception, std::list<Watch*> watches) {

		}

		void onMessage(DWORD severity, const char* format, ...) {

		}

	private:
		
};

int XDebug::port = 9000;
std::unordered_map<int, Client> XDebug::clients = std::unordered_map<int, Client>();
