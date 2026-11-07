// RSCapi.cpp — Social Club API 命令行替代工具
#pragma comment(lib, "winhttp.lib")

#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <cstring>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

// ============================================================
// 错误类型
// ============================================================
enum class Err { None, NotAuth, NoConnect, DataError };

static const char* ErrStr(Err e) {
    switch (e) {
    case Err::NotAuth:   return "NotAuth";
    case Err::NoConnect: return "NoConnect";
    case Err::DataError: return "DataError";
    default:             return "";
    }
}

// ============================================================
// 通用工具
// ============================================================
static std::string Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace((unsigned char)s[a])) ++a;
    while (b > a && isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

static std::wstring ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], len);
    return w;
}

// ============================================================
// SCAUTH 读取
// ============================================================
struct AuthConfig {
    std::string moduleName;
    uintptr_t address = 0;
    std::vector<uintptr_t> offsets;
};

static std::vector<uintptr_t> ParseOffsets(const std::string& line) {
    std::vector<uintptr_t> offsets;
    std::stringstream ss(line);
    std::string token;
    while (std::getline(ss, token, ',')) {
        token = Trim(token);
        if (token.empty()) continue;
        try {
            offsets.push_back((uintptr_t)std::stoull(token, nullptr, 16));
        }
        catch (...) {
            return {};
        }
    }
    return offsets;
}

// 严格解析单个十六进制 token：必须全部字符都是合法 hex，否则视为非法
static bool ParseHexToken(const std::string& token, uintptr_t& out) {
    if (token.empty()) return false;
    // 允许 "0x" 前缀
    std::string t = token;
    if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'))
        t = t.substr(2);
    if (t.empty()) return false;
    for (char c : t) {
        if (!isxdigit((unsigned char)c)) return false;
    }
    try {
        // uintptr_t 宽度与平台一致；用 unsigned long long 中转避免溢出告警
        unsigned long long v = std::stoull(t, nullptr, 16);
        out = (uintptr_t)v;
        return true;
    }
    catch (...) {
        return false;
    }
}

// 解析形如 "20,8,C8,50,208" 的偏移行；空行返回空 vector（合法：无偏移）
static bool ParseOffsets(const std::string& line, std::vector<uintptr_t>& out) {
    out.clear();
    if (line.empty()) return true;  // 空行 = 无偏移，合法
    std::stringstream ss(line);
    std::string token;
    bool first = true;
    while (std::getline(ss, token, ',')) {
        token = Trim(token);
        if (token.empty()) {
            // 允许末尾多余逗号，但中间的连续逗号视为非法
            if (!first) return false;
            first = false;
            continue;
        }
        uintptr_t off = 0;
        if (!ParseHexToken(token, off)) return false;
        out.push_back(off);
        first = false;
    }
    return true;
}

static bool LoadConfig(const std::string& path, AuthConfig& cfg) {
    std::ifstream f(path);
    if (!f) return false;

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        lines.push_back(line);
    }

    // 至少需要：模块名 + 地址
    if (lines.size() < 2) return false;

    cfg.moduleName = lines[0];
    if (cfg.moduleName.empty()) return false;

    if (!ParseHexToken(lines[1], cfg.address)) return false;

    // 偏移行可选：不存在则视为“无偏移”
    if (lines.size() >= 3) {
        if (!ParseOffsets(lines[2], cfg.offsets)) return false;
    }
    else {
        cfg.offsets.clear();
    }

    return true;
}

static DWORD FindPidByModule(const std::string& moduleName) {
    std::wstring wModule = ToWide(moduleName);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            HANDLE modSnap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
            if (modSnap == INVALID_HANDLE_VALUE) continue;

            MODULEENTRY32W me = {};
            me.dwSize = sizeof(me);
            if (Module32FirstW(modSnap, &me)) {
                do {
                    if (_wcsicmp(me.szModule, wModule.c_str()) == 0) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                } while (Module32NextW(modSnap, &me));
            }
            CloseHandle(modSnap);
            if (pid) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static uintptr_t GetModuleBase(DWORD pid, const std::string& moduleName) {
    std::wstring wModule = ToWide(moduleName);
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, wModule.c_str()) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

// 读取 SCAUTH，返回 NotAuth 表示失败
static Err ReadSCAuth(const std::string& configPath, std::string& out) {
    out.clear();
    AuthConfig cfg;
    if (!LoadConfig(configPath, cfg)) return Err::NotAuth;

    DWORD pid = FindPidByModule(cfg.moduleName);
    if (!pid) return Err::NotAuth;

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc) return Err::NotAuth;

    uintptr_t base = GetModuleBase(pid, cfg.moduleName);
    if (!base) { CloseHandle(hProc); return Err::NotAuth; }

    uintptr_t current = base + cfg.address;
    for (uintptr_t off : cfg.offsets) {
        uintptr_t p = 0;
        SIZE_T rd = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)current, &p, sizeof(p), &rd)
            || rd != sizeof(p)) {
            CloseHandle(hProc);
            return Err::NotAuth;
        }
        // 非法指针保护：低于 64KB 视为无效
        if (p < 0x10000) {
            CloseHandle(hProc);
            return Err::NotAuth;
        }
        current = p + off;
    }

    const SIZE_T kMax = 4096;
    std::vector<char> buf(kMax);
    SIZE_T rd = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)current, buf.data(), kMax, &rd)) {
        rd = 0;
        for (SIZE_T i = 0; i < kMax; ++i) {
            char c = 0; SIZE_T r = 0;
            if (!ReadProcessMemory(hProc, (LPCVOID)(current + i), &c, 1, &r)
                || r != 1) break;
            buf[i] = c;
            rd = i + 1;
            if (c == '\0') break;
        }
    }
    CloseHandle(hProc);

    if (rd == 0) return Err::NotAuth;

    auto it = std::find(buf.begin(), buf.begin() + rd, '\0');
    std::string s(buf.begin(), it);
    if (s.empty()) return Err::NotAuth;
    out = s;
    return Err::None;
}

// ============================================================
// WinHTTP 封装
// ============================================================
struct HttpResult {
    Err err = Err::None;
    std::string body;
};

static HttpResult HttpSend(const std::wstring& method,
    const std::wstring& path,
    const std::wstring& extraHeaders,
    const std::string& reqBody) {
    HttpResult res;

    HINTERNET session = WinHttpOpen(L"RSCapi/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { res.err = Err::NoConnect; return res; }

    HINTERNET connect = WinHttpConnect(session, L"scui.rockstargames.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        res.err = Err::NoConnect;
        return res;
    }

    HINTERNET request = WinHttpOpenRequest(connect, method.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        res.err = Err::NoConnect;
        return res;
    }

    std::wstring headers = extraHeaders;
    if (!headers.empty() && headers.back() != L'\n') headers += L"\r\n";

    BOOL ok = WinHttpSendRequest(
        request,
        headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
        headers.empty() ? 0 : (DWORD)-1L,
        reqBody.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)reqBody.data(),
        (DWORD)reqBody.size(),
        (DWORD)reqBody.size(),
        0);

    if (ok) ok = WinHttpReceiveResponse(request, nullptr);

    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        res.err = Err::NoConnect;
        return res;
    }

    // 检查 HTTP 状态码（非 200 一律视为通信失败）
    DWORD statusCode = 0, sz = sizeof(statusCode);
    WinHttpQueryHeaders(request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode, &sz, WINHTTP_NO_HEADER_INDEX);
    if (statusCode != 200) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        res.err = Err::NoConnect;
        return res;
    }

    DWORD avail = 0;
    do {
        avail = 0;
        if (!WinHttpQueryDataAvailable(request, &avail)) break;
        if (avail == 0) break;
        std::string chunk(avail, '\0');
        DWORD downloaded = 0;
        if (!WinHttpReadData(request, &chunk[0], avail, &downloaded)) break;
        res.body.append(chunk.data(), downloaded);
    } while (avail > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return res;
}

static std::wstring CommonHeaders(const std::string& scAuth) {
    return L"Authorization: SCAUTH val=\"" + ToWide(scAuth) + L"\"" +
        L"\r\nX-Title-Name: gta5" +
        L"\r\nX-Requested-With: XMLHttpRequest" +
        L"\r\nAccept: application/json, text/xml, */*";
}

// ============================================================
// API 实现
// ============================================================

// ---------- GetAvatars ----------
static HttpResult GetAvatars(const std::string& scAuth) {
    HttpResult r;
    std::wstring headers = CommonHeaders(scAuth) +
        L"\r\nContent-Type: application/json; charset=utf-8";
    std::string body = R"({"Title":"gta5"})";

    auto hr = HttpSend(L"POST", L"/api/profile/GetCustomAvatars", headers, body);
    if (hr.err != Err::None) return hr;

    try {
        json j = json::parse(hr.body);
        if (!j.is_array()) { r.err = Err::DataError; return r; }
        std::ostringstream oss;
        bool first = true;
        for (const auto& item : j) {
            if (!item.contains("i") || !item.contains("cid") ||
                !item.contains("src")) continue;
            if (!first) oss << ";";
            oss << item["i"].get<std::string>() << ","
                << item["cid"].get<std::string>() << ","
                << item["src"].get<std::string>();
            first = false;
        }
        r.body = oss.str();  // 无条目时为空
        return r;
    }
    catch (...) {
        r.err = Err::DataError;
        return r;
    }
}

// ---------- SetAvatars ----------
struct SetResult {
    Err err = Err::None;
    bool success = false;
};

static SetResult SetAvatars(const std::string& scAuth,
    const std::string& avatarId,
    const std::string& contextId) {
    SetResult r;
    json bodyJson = {
        {"AvatarUrl", ""},
        {"AvatarId", avatarId},
        {"AvatarContextId", contextId},
        {"CustomAvatar", true}
    };
    std::string body = bodyJson.dump();

    std::wstring headers = CommonHeaders(scAuth) +
        L"\r\nContent-Type: application/json; charset=utf-8" +
        L"\r\nContent-Length: " + std::to_wstring(body.size());

    auto hr = HttpSend(L"POST", L"/api/profile/UpdateAvatar", headers, body);
    if (hr.err != Err::None) { r.err = hr.err; return r; }

    try {
        json j = json::parse(hr.body);
        // 格式必须包含 Status 字段，否则视为格式错误
        if (!j.contains("Status")) { r.err = Err::DataError; return r; }
        r.success = j.value("Status", false);
        return r;
    }
    catch (...) {
        r.err = Err::DataError;
        return r;
    }
}

// ---------- GetCrew ----------
static HttpResult GetCrew(const std::string& scAuth) {
    HttpResult r;
    std::wstring headers = CommonHeaders(scAuth);
    auto hr = HttpSend(L"GET", L"/api/crew/getcrews", headers, "");
    if (hr.err != Err::None) return hr;

    try {
        json j = json::parse(hr.body);
        if (!j.contains("Crews") || !j["Crews"].is_array()) {
            r.err = Err::DataError;
            return r;
        }
        std::ostringstream oss;
        bool first = true;
        for (const auto& c : j["Crews"]) {
            if (!c.contains("CrewId") || !c.contains("CrewName") ||
                !c.contains("IsPrimary")) continue;
            if (!first) oss << ";";
            oss << c["CrewId"].get<long long>() << ","
                << c["CrewTag"].get<std::string>() << ","
                << (c["IsPrimary"].get<bool>() ? "true" : "false");
            first = false;
        }
        r.body = oss.str();
        return r;
    }
    catch (...) {
        r.err = Err::DataError;
        return r;
    }
}

// ---------- SetCrew ----------
static SetResult SetCrew(const std::string& scAuth, long long crewId) {
    SetResult r;
    json bodyJson = {
        {"crewId", crewId},
        {"opName", "active"}
    };
    std::string body = bodyJson.dump();

    std::wstring headers = CommonHeaders(scAuth) +
        L"\r\nContent-Type: application/json; charset=utf-8" +
        L"\r\nContent-Length: " + std::to_wstring(body.size());

    auto hr = HttpSend(L"POST", L"/api/crew/updatecrew", headers, body);
    if (hr.err != Err::None) { r.err = hr.err; return r; }

    try {
        json j = json::parse(hr.body);
        if (!j.contains("Status")) { r.err = Err::DataError; return r; }
        r.success = j.value("Status", false);
        return r;
    }
    catch (...) {
        r.err = Err::DataError;
        return r;
    }
}

std::filesystem::path GetExeDir()
{
    wchar_t buf[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len == 0 || len == MAX_PATH)
        return {};
    return std::filesystem::path(buf).parent_path();
}

// ============================================================
// main
// ============================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "DataError\n";
        return 1;
    }
    std::string cmd = argv[1];

    // ---- 先读取 SCAUTH，失败直接返回 NotAuth ----
    std::string scAuth;
    std::filesystem::path dataPath = GetExeDir() / L"RSCapi.dat";
    if (ReadSCAuth(dataPath.string(), scAuth) != Err::None) {
        std::cout << "NotAuth\n";
        return 1;
    }

    if (cmd == "GetAvatars") {
        auto r = GetAvatars(scAuth);
        if (r.err != Err::None) std::cout << ErrStr(r.err) << "\n";
        else                    std::cout << r.body << "\n";  // 空则空行
    }
    else if (cmd == "SetAvatars") {
        if (argc < 3) { std::cout << "DataError\n"; return 1; }
        std::string arg = argv[2];
        size_t comma = arg.find(',');
        if (comma == std::string::npos) {
            std::cout << "DataError\n";
            return 1;
        }
        std::string i = arg.substr(0, comma);
        std::string cid = arg.substr(comma + 1);
        if (i.empty() || cid.empty()) {
            std::cout << "DataError\n";
            return 1;
        }
        auto r = SetAvatars(scAuth, i, cid);
        if (r.err != Err::None) std::cout << ErrStr(r.err) << "\n";
        else                    std::cout << (r.success ? "True\n" : "False\n");
    }
    else if (cmd == "GetCrew") {
        auto r = GetCrew(scAuth);
        if (r.err != Err::None) std::cout << ErrStr(r.err) << "\n";
        else                    std::cout << r.body << "\n";
    }
    else if (cmd == "SetCrew") {
        if (argc < 3) { std::cout << "DataError\n"; return 1; }
        long long crewId = 0;
        try {
            crewId = std::stoll(argv[2]);
        }
        catch (...) {
            std::cout << "DataError\n";
            return 1;
        }
        auto r = SetCrew(scAuth, crewId);
        if (r.err != Err::None) std::cout << ErrStr(r.err) << "\n";
        else                    std::cout << (r.success ? "True\n" : "False\n");
    }
    else {
        std::cout << "DataError\n";
    }

    return 0;
}