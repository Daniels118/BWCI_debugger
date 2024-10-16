#include "utils.h"

#include <filesystem>
#include <fstream>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

struct HandleData {
    DWORD pid;
    HWND window;
    HWND excluding;
};

DWORD nop(LPVOID address, SIZE_T size) {
    DWORD oldProtect;
    if (VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BYTE* p = (BYTE*)address;
        for (SIZE_T i = 0; i < size; i++, p++) {
            *p = 0x90;
        }
        VirtualProtect(address, size, oldProtect, &oldProtect);
        return 0;
    }
    return GetLastError();
}

BOOL CALLBACK enumWindowsCallback(HWND handle, LPARAM lParam) {
    HandleData& data = *(HandleData*)lParam;
    DWORD pid = 0;
    GetWindowThreadProcessId(handle, &pid);
    if (data.pid != pid || handle == data.excluding) {
        return TRUE;
    }
    data.window = handle;
    return FALSE;
}

HWND findProcessWindowExcluding(DWORD pid, HWND excluding) {
    HandleData data;
    if (pid == NULL) {
        pid = GetCurrentProcessId();
    }
    data.pid = pid;
    data.window = 0;
    data.excluding = excluding;
    EnumWindows(enumWindowsCallback, (LPARAM)&data);
    return data.window;
}

bool alignWindow(HWND window, HWND ref, Anchor anchor) {
    RECT refRect;
    if (ref == NULL) {
        ref = GetDesktopWindow();
        SystemParametersInfo(SPI_GETWORKAREA, 0, &refRect, 0);
    } else {
        GetWindowRect(ref, &refRect);
    }
    RECT rect;
    GetWindowRect(window, &rect);
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    int x, y;
    switch (anchor) {
        case TOP_LEFT:
            x = refRect.left;
            y = refRect.top;
            break;
        case TOP_RIGHT:
            x = refRect.right - width;
            y = refRect.top;
            break;
        case BOTTOM_RIGHT:
            x = refRect.right - width;
            y = refRect.bottom - height;
            break;
        case BOTTOM_LEFT:
            x = refRect.left;
            y = refRect.bottom - height;
            break;
        default:
            return false;
    }
    return SetWindowPos(window, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

void setWindowPos(const HWND hwnd, const char* pos) {
    char* argv[2];
    if (streq(pos, "tl")) {
        alignWindow(hwnd, NULL, Anchor::TOP_LEFT);
    } else if (streq(pos, "tr")) {
        alignWindow(hwnd, NULL, Anchor::TOP_RIGHT);
    } else if (streq(pos, "br")) {
        alignWindow(hwnd, NULL, Anchor::BOTTOM_RIGHT);
    } else if (streq(pos, "bl")) {
        alignWindow(hwnd, NULL, Anchor::BOTTOM_LEFT);
    } else {
        char buf[32];
        strncpy(buf, pos, 32);
        int argc = splitArgs(buf, ',', argv, 2);
        if (argc == 2) {
            int x = atoi(argv[0]);
            int y = atoi(argv[1]);
            SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        } else {
            printf("Invalid coordinates.\n");
        }
    }
}

std::string pathToUrl(std::string path) {
    char buffer[MAX_PATH];
    DWORD size = MAX_PATH;
    UrlCreateFromPathA(path.c_str(), buffer, &size, NULL);
    return std::string(buffer);
}

std::string urlToPath(std::string url) {
    char buffer[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    HRESULT r = PathCreateFromUrlA(url.c_str(), buffer, &size, NULL);
    if (r != S_OK) {
        printf("PathCreateFromUrlA failed with error %i\n", r);
        return "";
    }
    return std::string(buffer);
}

std::string searchPaths(std::set<std::string> paths, std::string filename) {
    auto filepath = std::filesystem::path(filename);
    if (filepath.is_absolute()) {
        if (std::filesystem::exists(filepath)) {
            return filename;
        }
    } else {
        for (std::string path : paths) {
            for (const auto& entry : std::filesystem::directory_iterator(path)) {
                auto absPath = path / filepath;
                if (std::filesystem::exists(absPath)) {
                    return absPath.string();
                }
            }
        }
    }
    return "";
}

std::vector<std::string> readFile(std::filesystem::path path) {
    std::ifstream file(path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }
    return lines;
}

bool isNumber(const std::string& str) {
    std::istringstream iss(str);
    double val;
    iss >> val;
    return iss.eof() && !iss.fail();
}

const char* ltrim(const char* str) {
    while (*str != 0 && (*str == ' ' || *str == '\t')) {
        str++;
    }
    return str;
}

std::string strSnakeToCamel(std::string str) {
    std::string r;
    r.reserve(str.length());
    bool up = true;
    for (const char* pc = str.c_str(); *pc != 0; pc++) {
        char c = *pc;
        if (c == '_') {
            up = true;
        } else if (up) {
            r += toupper(c);
            up = false;
        } else {
            r += tolower(c);
        }
    }
    return r;
}

std::string strReplace(const std::string haystack, std::string needle, std::string replacement) {
    std::string str = haystack;
    const size_t nLen = needle.length();
    if (nLen == 0) return str;
    const size_t rLen = replacement.length();
    size_t index = 0;
    while (true) {
        index = str.find(needle, index);
        if (index == std::string::npos) break;
        str.replace(index, nLen, replacement);
        index += rLen;
    }
    return str;
}

bool strin(const char* str, ...) {
    va_list args;
    va_start(args, str);
    int count = va_arg(args, int);
    bool res = false;
    for (int i = 0; i < count; ++i) {
        if (streq(str, (char*)va_arg(args, int))) {
            res = true;
            break;
        }
    }
    va_end(args);
    return res;
}

bool strEndsWith(const char* str, const char* suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    return str_len >= suffix_len && !memcmp(str + str_len - suffix_len, suffix, suffix_len);
}

const char* strrpbrk(const char* str, const char* chrs) {
    if (str == NULL || chrs == NULL || *str == 0 || *chrs == 0) return NULL;
    for (int i = strlen(str) - 1; i >= 0; i--) {
        for (const char* pc = chrs; *pc != 0; pc++) {
            if (*pc == str[i]) return &(str[i]);
        }
    }
    return NULL;
}

int rejoinArgsC(char** argv, int argc, int startIndex, int count) {
    for (int i = startIndex + 1; i < MIN(startIndex + count, argc); i++) {
        char* arg = argv[i];
        arg[-1] = ' ';
        argc--;
    }
    return argc;
}

int rejoinArgs(char** argv, int argc, const char* startArg, const char* endArg) {
    int endIndex = argc;
    for (int i = argc - 1; i >= 0; i--) {
        if (argv[i] == endArg) {
            endIndex = i;
        } else if (argv[i] == startArg) {
            return rejoinArgsC(argv, argc, i, endIndex - i);
            break;
        }
    }
    return argc;
}

int splitArgs(char* str, char sep, char** dst, int limit) {
    int n = 0, i = 0;
    bool quote = false;
    bool escape = false;
    dst[n++] = str;
    if (n >= limit) return n;
    bool isQuote = false;
    while (str[i] != 0) {
        if (str[i] == '"') {
            str[i] = 0;         //Remove the quotes from the result
            quote = !quote;
            if (quote) {
                dst[n - 1]++;   //Skip the opening quote
                isQuote = true;
            }
        } else if (str[i] == sep && !quote) {
            str[i] = 0;
            if (dst[n - 1][0] == 0 && !isQuote) {
                n--;            //Skip empty args, unless they are empty quotes
            }
            dst[n++] = &str[i + 1];
            if (n >= limit) return n;
            isQuote = false;
        }
        i++;
    }
    return n;
}

int getArgIndex(char** argv, int argc, const char* arg) {
    for (int i = 0; i < argc; i++) {
        if (streq(argv[i], arg)) {
            return i;
        }
    }
    return -1;
}

bool getArgFlag(char** argv, int argc, const char* arg) {
    return getArgIndex(argv, argc, arg) >= 0;
}

char* getArgVal(char** argv, int argc, const char* arg) {
    return getArgValOrDefault(argv, argc, arg, NULL);
}

char* getArgValOrDefault(char** argv, int argc, const char* arg, const char* def) {
    int index = getArgIndex(argv, argc, arg);
    if (index < 0 || index >= argc - 1) return (char*)def;
    return argv[index + 1];
}


static const DWORD crc_table[256] = {
    0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
    0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
    0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
    0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
    0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
    0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
    0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
    0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
    0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
    0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
    0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
    0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
    0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
    0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
    0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
    0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
    0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
    0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
    0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
    0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
    0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
    0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
    0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
    0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
    0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
    0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
    0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
    0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
    0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
    0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
    0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
    0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
    0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
    0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
    0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
    0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
    0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
    0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
    0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
    0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
    0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
    0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
    0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
    0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
    0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
    0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
    0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
    0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
    0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
    0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
    0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
    0x2d02ef8dL
};

#define DO1(buf) crc = crc_table[((int)crc ^ (*buf++)) & 0xff] ^ (crc >> 8);
#define DO2(buf)  DO1(buf); DO1(buf);
#define DO4(buf)  DO2(buf); DO2(buf);
#define DO8(buf)  DO4(buf); DO4(buf);

DWORD crc32(DWORD crc, char* buf, size_t len) {
    if (buf == NULL) return 0;
    crc = crc ^ 0xFFFFFFFF;
    while (len >= 8) {
        DO8(buf);
        len -= 8;
    }
    if (len) {
        do {
            DO1(buf);
        } while (--len);
    }
    return crc ^ 0xFFFFFFFF;
}

bool crc32file(const char* filename, DWORD* outHash) {
    DWORD crc = 0;
    FILE* file = fopen(filename, "rb");
    if (file == NULL) return false;
    char buffer[1024];
    size_t n = fread(buffer, 1, 1024, file);
    while (n > 0) {
        crc = crc32(crc, buffer, n);
        n = fread(buffer, 1, 1024, file);
    }
    fclose(file);
    *outHash = crc;
    return true;
}
