// main.cpp
// USBwatcher - detect special file on removable drives, kill/restart process trees.
// Build: Visual Studio (x86/x64). Requires wbemuuid.lib for WMI (command line retrieval).
// Author: Generated per user spec. Read comments for details.

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <filesystem>
#include <map>
#include <algorithm>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")


namespace fs = std::filesystem;

// --------------------------- Utilities ------------------------------------

static const char* DEFAULT_CONFIG_TEXT =
"# USBwatcher config.inf (key=value)\n"
"filename=special.txt\n"
"filecontent=123456\n"
"interval_seconds=1\n"
"target_process=example.exe\n"
"log_retention_days=14\n";

static std::wstring to_wstring(const std::string& s) {
    if (s.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w; w.resize(sz);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], sz);
    return w;
}
static std::string to_string(const std::wstring& w) {
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s; s.resize(sz);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], sz, NULL, NULL);
    return s;
}
static std::string now_timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm; localtime_s(&tm, &t);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buf);
}
static std::string today_date() {
    std::time_t t = std::time(nullptr);
    std::tm tm; localtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d", &tm);
    return std::string(buf);
}

// --------------------------- Logging --------------------------------------

class Logger {
public:
    Logger(const fs::path& baseDir, int retentionDays)
        : baseDir_(baseDir), retentionDays_(retentionDays) {
        try {
            fs::create_directories(baseDir_);
        }
        catch (...) {}
        openLogFile();
        cleanupOldLogs();
    }
    ~Logger() {
        if (ofs_.is_open()) ofs_.close();
    }
    void log(const std::string& line) {
        std::lock_guard<std::mutex> lk(mu_);
        std::string entry = now_timestamp() + " " + line + "\n";
        if (ofs_.is_open()) {
            ofs_ << entry;
            ofs_.flush();
        }
        // Also optionally echo to console if console visible
        if (consoleVisible_) {
            std::cout << entry;
        }
    }
    void setConsoleVisible(bool v) { consoleVisible_ = v; }
private:
    fs::path baseDir_;
    std::ofstream ofs_;
    std::mutex mu_;
    int retentionDays_ = 14;
    bool consoleVisible_ = false;

    void openLogFile() {
        std::string fname = "USBwatcher_" + today_date() + ".log";
        fs::path p = baseDir_ / fname;
        ofs_.open(p.string(), std::ios::app);
        if (!ofs_.is_open()) {
            // fallback to stdout
        }
    }
    void cleanupOldLogs() {
        try {
            for (auto& entry : fs::directory_iterator(baseDir_)) {
                if (!entry.is_regular_file()) continue;
                auto p = entry.path();
                auto fname = p.filename().string();
                // match pattern USBwatcher_YYYYMMDD.log
                if (fname.rfind("USBwatcher_", 0) == 0 && fname.size() >= 19) {
                    // parse date
                    std::string datepart = fname.substr(11, 8);
                    std::tm tm = {};
                    if (strptime(datepart.c_str(), "%Y%m%d", &tm) != nullptr) {
                        std::time_t filetime = mktime(&tm);
                        std::time_t now = std::time(nullptr);
                        double days = difftime(now, filetime) / (60 * 60 * 24);
                        if (days > retentionDays_) {
                            try { fs::remove(p); }
                            catch (...) {}
                        }
                    }
                }
            }
        }
        catch (...) {}
    }
    // strptime helper for Windows
    static char* strptime(const char* s, const char* f, std::tm* tm) {
        // Very small implementation for YYYYMMDD only
        if (strlen(f) >= 6 && strstr(f, "%Y") && strstr(f, "%m") && strstr(f, "%d")) {
            int Y, M, D;
            if (sscanf_s(s, "%4d%2d%2d", &Y, &M, &D) == 3) {
                tm->tm_year = Y - 1900;
                tm->tm_mon = M - 1;
                tm->tm_mday = D;
                return (char*)s + 8;
            }
        }
        return nullptr;
    }
};

// --------------------------- Config ---------------------------------------

struct Config {
    std::string filename = "special.txt";
    std::string filecontent = "123456";
    int interval_seconds = 1;
    std::vector<std::string> target_processes = { "example.exe" };
    int log_retention_days = 14;
};

static Config loadConfig(const fs::path& cfgPath) {
    Config cfg;
    if (!fs::exists(cfgPath)) return cfg;
    std::ifstream ifs(cfgPath.string());
    std::string line;
    while (std::getline(ifs, line)) {
        // trim
        auto pos = line.find('#');
        if (pos != std::string::npos) line = line.substr(0, pos);
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        // trim spaces
        auto trim = [](std::string& s) {
            while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());
            while (!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
            };
        trim(key); trim(val);
        if (key == "filename") cfg.filename = val;
        else if (key == "filecontent") cfg.filecontent = val;
        else if (key == "interval_seconds") {
            try { cfg.interval_seconds = (std::max)(1, std::stoi(val)); }
            catch (...) {}
        }
        else if (key == "target_process") {
            cfg.target_processes.clear();
            // split by comma
            std::stringstream ss(val);
            std::string item;
            while (std::getline(ss, item, ',')) {
                // trim
                while (!item.empty() && isspace((unsigned char)item.front())) item.erase(item.begin());
                while (!item.empty() && isspace((unsigned char)item.back())) item.pop_back();
                if (!item.empty()) cfg.target_processes.push_back(item);
            }
            if (cfg.target_processes.empty()) cfg.target_processes.push_back("example.exe");
        }
        else if (key == "log_retention_days") {
            try { cfg.log_retention_days = (std::max)(1, std::stoi(val)); }
            catch (...) {}
        }
    }
    return cfg;
}

// --------------------------- WMI helper to get command line -----------------
// Uses WMI to query Win32_Process.CommandLine for a given PID.
// --------------------------- WMI helper to get command line -----------------
// Uses WMI to query Win32_Process.CommandLine for a given PID.
static bool getProcessCommandLineWMI(DWORD pid, std::wstring& outCmd) {
    // Declare variables up front so goto cleanup won't skip construction
    std::wstring query;
    bool ok = false;
    HRESULT hres = S_OK;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IEnumWbemClassObject* pEnumerator = nullptr;
    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;

    // Initialize COM
    hres = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool coInited = SUCCEEDED(hres);

    // Initialize security
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) goto cleanup;

    // Obtain the initial locator to WMI
    hres = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres) || pLoc == nullptr) goto cleanup;

    // Connect to WMI namespace
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres) || pSvc == nullptr) goto cleanup;

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) goto cleanup;

    // Build query string safely (left operand is std::wstring)
    query = std::wstring(L"SELECT CommandLine FROM Win32_Process WHERE ProcessId=") + std::to_wstring(pid);

    // Execute the query
    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres) || pEnumerator == nullptr) goto cleanup;

    // Retrieve results
    while (true) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (FAILED(hr) || uReturn == 0) break;
        VARIANT vtProp;
        VariantInit(&vtProp);
        hr = pclsObj->Get(L"CommandLine", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal) {
            outCmd = vtProp.bstrVal;
            VariantClear(&vtProp);
            ok = true;
        }
        else {
            VariantClear(&vtProp);
        }
        pclsObj->Release();
        pclsObj = nullptr;
    }

cleanup:
    if (pEnumerator) { pEnumerator->Release(); pEnumerator = nullptr; }
    if (pSvc) { pSvc->Release(); pSvc = nullptr; }
    if (pLoc) { pLoc->Release(); pLoc = nullptr; }
    if (coInited) CoUninitialize();
    return ok;
}


// --------------------------- Process utilities -----------------------------

struct KilledProcessInfo {
    DWORD pid;
    std::wstring exePath;
    std::wstring cmdLine;
    std::wstring workingDir;
};

static std::wstring getProcessImagePath(DWORD pid) {
    std::wstring path;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        WCHAR buf[MAX_PATH];
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
            path = buf;
        }
        CloseHandle(h);
    }
    return path;
}

// Build parent->children map for current processes
static void buildProcessTree(std::map<DWORD, std::vector<DWORD>>& children, std::map<DWORD, DWORD>& parent) {
    children.clear(); parent.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            parent[pe.th32ProcessID] = pe.th32ParentProcessID;
            children[pe.th32ParentProcessID].push_back(pe.th32ProcessID);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// Find all PIDs whose exe name matches target (case-insensitive)
static std::vector<DWORD> findProcessesByName(const std::string& name) {
    std::vector<DWORD> res;
    std::string lowerName = name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return res;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            std::string exe = to_string(pe.szExeFile);
            std::string exeLower = exe;
            std::transform(exeLower.begin(), exeLower.end(), exeLower.begin(), ::tolower);
            if (exeLower == lowerName) {
                res.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return res;
}

// Recursively collect subtree PIDs given root pid
static void collectSubtreePids(DWORD root, const std::map<DWORD, std::vector<DWORD>>& children, std::vector<DWORD>& out) {
    out.push_back(root);
    auto it = children.find(root);
    if (it != children.end()) {
        for (DWORD c : it->second) {
            collectSubtreePids(c, children, out);
        }
    }
}

// Force kill a process by PID
static bool forceKillProcess(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return false;
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok == TRUE;
}

// --------------------------- Global state ---------------------------------

static std::atomic<bool> g_running{ true };
static std::atomic<bool> g_threadA_running{ false };
static std::mutex g_threadA_mutex;
static std::thread g_threadA;
static Logger* g_logger = nullptr;
static Config g_config;
static std::vector<KilledProcessInfo> g_killedRecords; // in-memory only
static std::mutex g_killedMutex;
static std::string g_triggerDrive; // which drive triggered

// --------------------------- Dialog with timeout --------------------------
// Use a custom simple dialog implemented via MessageBoxTimeout if available,
// otherwise emulate with a thread that posts WM_CLOSE after timeout.

typedef int (WINAPI* MessageBoxTimeoutW_t)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);

static int MessageBoxTimeoutWrapper(HWND hwnd, LPCWSTR text, LPCWSTR caption, UINT type, DWORD timeoutMs) {
    HMODULE hUser = LoadLibraryW(L"user32.dll");
    if (hUser) {
        auto p = (FARPROC)GetProcAddress(hUser, "MessageBoxTimeoutW");
        if (p) {
            MessageBoxTimeoutW_t mbt = (MessageBoxTimeoutW_t)p;
            int r = mbt(hwnd, text, caption, type, 0, timeoutMs);
            FreeLibrary(hUser);
            return r;
        }
        FreeLibrary(hUser);
    }
    // fallback: create a thread to auto-close a MessageBox after timeout
    struct MBCTX { HWND owner; DWORD timeout; };
    MBCTX ctx{ hwnd, timeoutMs };
    // create a thread that finds the message box and closes it after timeout
    std::atomic<bool> closed{ false };
    std::thread t([&closed, timeoutMs]() {
        DWORD start = GetTickCount();
        while (!closed && GetTickCount() - start < timeoutMs) {
            Sleep(100);
        }
        // try to find top-level message box windows and send IDYES
        HWND h = NULL;
        EnumWindows([](HWND hwnd, LPARAM lparam)->BOOL {
            wchar_t cls[256]; GetClassNameW(hwnd, cls, _countof(cls));
            // MessageBox class is #32770
            if (wcscmp(cls, L"#32770") == 0) {
                // send IDYES
                PostMessageW(hwnd, WM_COMMAND, IDYES, 0);
            }
            return TRUE;
            }, 0);
        closed = true;
        });
    int ret = MessageBoxW(hwnd, text, caption, type);
    closed = true;
    if (t.joinable()) t.join();
    return ret;
}

// Show custom dialog with Yes/No and 5s auto-yes
static bool showYesNoDialogWithTimeout(const std::wstring& title, const std::wstring& text, int timeoutSeconds) {
    DWORD timeoutMs = timeoutSeconds * 1000;
    int r = MessageBoxTimeoutWrapper(NULL, text.c_str(), title.c_str(), MB_YESNO | MB_TOPMOST | MB_SYSTEMMODAL, timeoutMs);
    return (r == IDYES);
}

// --------------------------- Thread A: kill loop ---------------------------

static void threadA_func() {
    {
        std::lock_guard<std::mutex> lk(g_threadA_mutex);
        if (g_threadA_running) return; // already running
        g_threadA_running = true;
    }
    g_logger->log("Thread A started.");
    while (g_running && g_threadA_running) {
        try {
            // Build process tree map
            std::map<DWORD, std::vector<DWORD>> children;
            std::map<DWORD, DWORD> parent;
            buildProcessTree(children, parent);

            // For each configured target process name, find matching PIDs
            std::vector<DWORD> targets;
            for (auto& tname : g_config.target_processes) {
                auto found = findProcessesByName(tname);
                for (auto pid : found) targets.push_back(pid);
            }
            // Deduplicate
            std::sort(targets.begin(), targets.end());
            targets.erase(std::unique(targets.begin(), targets.end()), targets.end());

            if (!targets.empty()) {
                g_logger->log("Thread A: found target processes to kill. Trigger drive: " + g_triggerDrive);
            }

            // For each target root, collect subtree and kill
            for (DWORD rootPid : targets) {
                std::vector<DWORD> subtree;
                collectSubtreePids(rootPid, children, subtree);
                // Sort subtree so we kill children before parents (descending by depth)
                // Simple approach: sort descending by PID count? We'll kill in reverse order of discovery
                std::reverse(subtree.begin(), subtree.end());
                for (DWORD pid : subtree) {
                    // record info before killing
                    KilledProcessInfo info;
                    info.pid = pid;
                    info.exePath = getProcessImagePath(pid);
                    // get command line via WMI
                    std::wstring cmd;
                    if (getProcessCommandLineWMI(pid, cmd)) info.cmdLine = cmd;
                    else info.cmdLine = L"";
                    // working dir not easily available; leave empty
                    {
                        std::lock_guard<std::mutex> lk(g_killedMutex);
                        g_killedRecords.push_back(info);
                    }
                    // attempt to kill
                    bool ok = forceKillProcess(pid);
                    std::ostringstream ss;
                    ss << "Thread A: kill pid=" << pid << " exe=" << to_string(info.exePath)
                        << " cmd=\"" << to_string(info.cmdLine) << "\" result=" << (ok ? "OK" : "FAIL");
                    g_logger->log(ss.str());
                }
            }
        }
        catch (const std::exception& ex) {
            g_logger->log(std::string("Thread A exception: ") + ex.what());
        }
        catch (...) {
            g_logger->log("Thread A unknown exception.");
        }

        // sleep interval
        for (int i = 0; i < g_config.interval_seconds && g_running && g_threadA_running; ++i) Sleep(1000);
    }
    g_logger->log("Thread A exiting.");
    g_threadA_running = false;
}

// Stop thread A and attempt to restore killed processes
static void stopThreadAAndRestore() {
    {
        std::lock_guard<std::mutex> lk(g_threadA_mutex);
        if (!g_threadA_running) return;
        g_threadA_running = false;
    }
    // join thread if running
    if (g_threadA.joinable()) {
        g_threadA.join();
    }
    g_logger->log("Thread A stopped; attempting to restore killed processes.");
    // Restore processes from g_killedRecords in memory.
    // We will attempt to start processes from roots first. Since we recorded in kill order (children first),
    // we can attempt to restart in reverse order (which should be root-first).
    std::vector<KilledProcessInfo> toRestore;
    {
        std::lock_guard<std::mutex> lk(g_killedMutex);
        toRestore = g_killedRecords;
        g_killedRecords.clear();
    }
    // reverse toRestore so roots are first (we recorded children first)
    std::reverse(toRestore.begin(), toRestore.end());
    for (auto& info : toRestore) {
        if (info.exePath.empty()) {
            g_logger->log("Restore: missing exe path for pid " + std::to_string(info.pid) + ", skip.");
            continue;
        }
        // Build command line: if cmdLine available, use it; else use exe path
        std::wstring cmdline = info.cmdLine.empty() ? info.exePath : info.cmdLine;
        // CreateProcess requires mutable buffer
        std::wstring cmd = cmdline;
        STARTUPINFOW si; PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        BOOL ok = CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
        if (ok) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            g_logger->log("Restore: started " + to_string(info.exePath) + " cmd=\"" + to_string(cmdline) + "\"");
        }
        else {
            DWORD err = GetLastError();
            std::ostringstream ss;
            ss << "Restore: failed to start " << to_string(info.exePath) << " error=" << err;
            g_logger->log(ss.str());
        }
        Sleep(200); // small delay between restarts
    }
}

// --------------------------- Drive detection ------------------------------

static bool isRemovableDrive(char driveLetter) {
    wchar_t rootPath[8] = L"X:\\";
    rootPath[0] = (wchar_t)driveLetter;
    UINT type = GetDriveTypeW(rootPath);
    return type == DRIVE_REMOVABLE;
}

static std::vector<std::string> listRemovableRoots() {
    std::vector<std::string> res;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (mask & (1 << i)) {
            char drive = 'A' + i;
            if (isRemovableDrive(drive)) {
                std::string root; root.push_back(drive); root += ":\\";
                res.push_back(root);
            }
        }
    }
    return res;
}

// Check if any removable root contains the special file with exact content
static bool checkSpecialFileOnRemovable(const Config& cfg, std::string& outDrive) {
    auto roots = listRemovableRoots();
    for (auto& r : roots) {
        fs::path p = fs::path(r) / cfg.filename;
        if (fs::exists(p) && fs::is_regular_file(p)) {
            // read file content exactly
            std::ifstream ifs(p.string(), std::ios::binary);
            std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            // exact match, no trimming
            if (content == cfg.filecontent) {
                outDrive = r;
                return true;
            }
        }
    }
    return false;
}

// --------------------------- Single instance ------------------------------

static HANDLE createSingleInstanceMutex() {
    HANDLE h = CreateMutexW(NULL, FALSE, L"Global\\USBwatcher_CreaconceptionStudio_Wajirui_v1");
    if (!h) return NULL;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(h);
        return NULL;
    }
    return h;
}

// --------------------------- Config  Exists ------------------------------
// 确保 config 文件存在，若不存在则创建默认文件
static void ensureConfigExists(const fs::path& cfgPath, Logger* logger = nullptr) {
    try {
        if (!fs::exists(cfgPath)) {
            std::ofstream ofs(cfgPath.string(), std::ios::out | std::ios::trunc);
            if (ofs.is_open()) {
                ofs << DEFAULT_CONFIG_TEXT;
                ofs.close();
                if (logger) logger->log("Config not found. Created default config.inf.");
            }
            else {
                if (logger) logger->log("Failed to create default config.inf (ofstream open failed).");
            }
        }
        else {
            if (logger) logger->log("Config found: " + cfgPath.string());
        }
    }
    catch (const std::exception& ex) {
        if (logger) logger->log(std::string("ensureConfigExists exception: ") + ex.what());
    }
    catch (...) {
        if (logger) logger->log("ensureConfigExists unknown exception.");
    }
}

// --------------------------- Main -----------------------------------------

int wmain(int argc, wchar_t* argv[]) {
    // Determine if console should be visible (control param)
    bool consoleMode = false;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        std::transform(a.begin(), a.end(), a.begin(), ::towlower);
        if (a == L"control") consoleMode = true;
    }

    // Single instance
    HANDLE single = createSingleInstanceMutex();
    if (!single) {
        MessageBoxW(NULL, L"USBwatcher is already running.", L"USBwatcher", MB_OK | MB_ICONEXCLAMATION);
        return 0;
    }

    // Hide console if not control
    HWND consoleWnd = GetConsoleWindow();
    if (!consoleMode && consoleWnd) {
        ShowWindow(consoleWnd, SW_HIDE);
    }
    else {
        if (consoleWnd) ShowWindow(consoleWnd, SW_SHOW);
    }

    // Setup paths
    wchar_t exePathW[MAX_PATH];
    GetModuleFileNameW(NULL, exePathW, MAX_PATH);
    fs::path exePath = exePathW;
    fs::path baseDir = exePath.parent_path();
    fs::path logDir = baseDir / "log";
    fs::path cfgPath = baseDir / "config.inf";
    ensureConfigExists(cfgPath, nullptr);

    // Load config
    g_config = loadConfig(cfgPath);

    // Logger
    Logger logger(logDir, g_config.log_retention_days);
    g_logger = &logger;
    g_logger->setConsoleVisible(consoleMode);
    g_logger->log("USBwatcher starting.");
    g_logger->log("Config: filename=" + g_config.filename + " filecontent=" + g_config.filecontent
        + " interval=" + std::to_string(g_config.interval_seconds));
    {
        std::ostringstream ss;
        ss << "Target processes:";
        for (auto& t : g_config.target_processes) ss << " " << t;
        g_logger->log(ss.str());
    }

    // Main loop: detect special file on removable drives
    bool longTermMode = false;
    bool threadA_started_once = false;

    while (g_running) {
        try {
            std::string detectedDrive;
            bool found = checkSpecialFileOnRemovable(g_config, detectedDrive);
            if (found) {
                g_triggerDrive = detectedDrive;
                g_logger->log("Detected special file on drive: " + detectedDrive);
                // Show dialog first (custom with timeout)
                std::wstring title = L"USBwatcher";
                std::wstring text = std::wstring(L"Detected special file on drive ")
                    + std::wstring(detectedDrive.begin(), detectedDrive.end())
                    + std::wstring(L"\nDo you want to run long-term?");
                bool userYes = showYesNoDialogWithTimeout(title, text, 5);
                std::ostringstream ss; ss << "User choice: " << (userYes ? "Yes" : "No");
                g_logger->log(ss.str());

                if (userYes) {
                    // Start thread A (if not already)
                    if (!g_threadA_running) {
                        g_killedRecords.clear();
                        g_threadA = std::thread(threadA_func);
                        threadA_started_once = true;
                    }
                    // Enter long-term mode: stop detection loop
                    longTermMode = true;
                    g_logger->log("Entering long-term mode. Main detection loop paused.");
                    // Wait here until special file disappears (we still want thread A running)
                    while (longTermMode && g_running) {
                        // Check if special file still present; if removed, exit long-term mode and stop thread A
                        std::string dd;
                        bool still = checkSpecialFileOnRemovable(g_config, dd);
                        if (!still) {
                            g_logger->log("Special file disappeared while in long-term mode. Stopping thread A and restoring.");
                            stopThreadAAndRestore();
                            longTermMode = false;
                            break;
                        }
                        Sleep(1000);
                    }
                }
                else {
                    // User chose No: start thread A briefly then stop when file disappears
                    if (!g_threadA_running) {
                        g_killedRecords.clear();
                        g_threadA = std::thread(threadA_func);
                        threadA_started_once = true;
                    }
                    // Continue detection but do not start additional thread A instances
                    // Wait until file disappears or content invalid or drive removed
                    while (g_running) {
                        std::string dd;
                        bool still = checkSpecialFileOnRemovable(g_config, dd);
                        if (!still) {
                            g_logger->log("Special file disappeared after user chose No. Stopping thread A and restoring.");
                            stopThreadAAndRestore();
                            break;
                        }
                        Sleep(1000);
                    }
                }
            }
        }
        catch (const std::exception& ex) {
            g_logger->log(std::string("Main loop exception: ") + ex.what());
        }
        catch (...) {
            g_logger->log("Main loop unknown exception.");
        }

        // Sleep interval
        for (int i = 0; i < g_config.interval_seconds && g_running && !longTermMode; ++i) Sleep(1000);
    }

    // Cleanup on exit
    g_logger->log("USBwatcher exiting.");
    stopThreadAAndRestore();
    if (single) CloseHandle(single);
    return 0;
}
