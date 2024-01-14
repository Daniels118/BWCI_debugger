#pragma once

#include <string.h>
#include <set>
#include <vector>
#include <string>
#include <filesystem>
#include <windows.h>

enum Anchor {
	TOP_LEFT, TOP_RIGHT, BOTTOM_RIGHT, BOTTOM_LEFT
};

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define streq(STRING1, STRING2) strcmp(STRING1, STRING2) == 0

DWORD nop(LPVOID address, SIZE_T size);

HWND findMainWindow(DWORD pid);
BOOL isMainWindow(HWND handle);
bool alignWindow(HWND window, HWND ref, Anchor side);

std::string searchPaths(std::set<std::string> paths, std::string subpath);
std::vector<std::string> readFile(std::filesystem::path path);

bool isNumber(const std::string& str);

std::string strReplace(const std::string haystack, std::string needle, std::string replacement);

int rejoinArgsC(char** argv, int argc, int startIndex, int count);
int rejoinArgs(char** argv, int argc, const char* startArg, const char* endArg);

int splitArgs(char* str, char sep, char** dst, int limit);

int getArgIndex(char** argv, int argc, const char* arg);
bool getArgFlag(char** argv, int argc, const char* arg);
char* getArgVal(char** argv, int argc, const char* arg);

DWORD crc32(DWORD crc, char* buf, size_t len);
bool crc32file(const char* filename, DWORD* outHash);
