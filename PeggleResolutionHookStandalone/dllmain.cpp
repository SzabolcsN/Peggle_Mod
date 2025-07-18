#include "pch.h"
#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <vector>
#include <string>
#include <cwctype>
#include <algorithm>
#include <Psapi.h>

// Configuration
constexpr DWORD DESIRED_WIDTH = 1280;
constexpr DWORD DESIRED_HEIGHT = 720;
constexpr const char* GAME_EXECUTABLE = "Peggle.exe";
constexpr const wchar_t* GAME_WINDOW_CLASS = L"POPFramework";  // Most common class name

// Global log file
std::ofstream logFile;

// Logging function
void Log(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (logFile.is_open()) {
        logFile << buffer << std::endl;
        logFile.flush();
    }
    OutputDebugStringA(buffer);
}

// Convert wide string to lower case
std::wstring to_lower(const std::wstring& str) {
    std::wstring lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    return lower;
}

// Find the actual Peggle game window
HWND FindPeggleWindow() {
    HWND hwnd = nullptr;

    // Enumerate all top-level windows
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        // Check if window is visible
        if (!IsWindowVisible(hwnd)) return TRUE;

        // Get process ID
        DWORD processId;
        GetWindowThreadProcessId(hwnd, &processId);

        // Get process name
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) return TRUE;

        wchar_t processName[MAX_PATH] = L"";
        if (GetModuleFileNameExW(hProcess, NULL, processName, MAX_PATH)) {
            std::wstring lowerName = to_lower(processName);
            if (lowerName.find(L"peggle") != std::wstring::npos) {
                *reinterpret_cast<HWND*>(lParam) = hwnd;
                CloseHandle(hProcess);
                return FALSE; // Stop enumeration
            }
        }
        CloseHandle(hProcess);
        return TRUE;
        }, reinterpret_cast<LPARAM>(&hwnd));

    return hwnd;
}

// Force window size and position
void SetGameWindowSize() {
    HWND hwnd = FindPeggleWindow();
    if (!hwnd) {
        Log("Game window not found");
        return;
    }

    // Get current window style
    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);

    // Calculate required window size
    RECT rc = { 0, 0, DESIRED_WIDTH, DESIRED_HEIGHT };
    AdjustWindowRectEx(&rc, style, FALSE, exStyle);

    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    // Get screen dimensions
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Center window
    int x = (screenWidth - width) / 2;
    int y = (screenHeight - height) / 2;

    // Apply new size and position
    SetWindowPos(hwnd, NULL, x, y, width, height,
        SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);

    Log("Set window size to %dx%d (position: %d, %d)", width, height, x, y);

    // Get window class for debugging
    wchar_t className[256] = L"";
    GetClassNameW(hwnd, className, 256);
    Log("Game window class: %ls", className);
}

// Main initialization
void Initialize() {
    logFile.open("PeggleResolutionHook.log", std::ios::out | std::ios::trunc);
    Log("==== Peggle Resolution Hook Initialized ====");

    // Set window size immediately
    SetGameWindowSize();

    // Set up periodic resizing
    SetTimer(NULL, 0, 1000, [](HWND, UINT, UINT_PTR, DWORD) {
        SetGameWindowSize();
        });
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            Initialize();
            return 0;
            }, nullptr, 0, nullptr);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("DLL unloaded");
        if (logFile.is_open()) logFile.close();
    }
    return TRUE;
}