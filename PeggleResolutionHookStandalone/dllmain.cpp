#include "pch.h"
#include <Windows.h>
#include <fstream>
#include <thread>
#include <vector>
#include <Psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

// Configuration
constexpr int TARGET_WIDTH = 1280;
constexpr int TARGET_HEIGHT = 960;
constexpr const wchar_t* WINDOW_CLASS = L"MainWindow";

// Global log file
std::ofstream logFile;

// Candidate addresses list
const uintptr_t candidateAddresses[] = {
    0x03AC5BB8, 0x03AC5C30, 0x03AC89B8, 0x03AC8A30,
    0x03ACB7B8, 0x03ACB830, 0x03ACE5B8, 0x03ACE630,
    0x03AD13B8, 0x03AD1430, 0x03AD41B8, 0x03AD4230,
    0x03AD7038, 0x03AD70B0, 0x03AD9E38, 0x03AD9EB0,
    0x03ADCC38, 0x03ADCCB0, 0x03ADFA38, 0x03ADFAB0,
    0x03AE2838, 0x03AE28B0, 0x03AE5638, 0x03AE56B0,
    0x03AE8438, 0x03AE84B0, 0x03AEB238, 0x03AEB2B0,
    0x03AF1938, 0x03AF19B0, 0x03AF7538, 0x03AF75B0,
    0x03AFA338, 0x03AFA3B0, 0x03AFD138, 0x03AFD1B0,
    0x03AFFFB8, 0x03B00030, 0x03B02DB8, 0x03B02E30
};

const size_t numCandidates = sizeof(candidateAddresses) / sizeof(candidateAddresses[0]);

void Log(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (logFile.is_open()) {
        logFile << buffer << std::endl;
    }
    OutputDebugStringA(buffer);
}

// Helper function for SEH-safe memory operations
int SafeReadAddress(uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        return -1;
    }

    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
        return -1;
    }

    __try {
        return *reinterpret_cast<int*>(addr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

bool SafeWriteAddress(uintptr_t addr, int value) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        return false;
    }

    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)addr, sizeof(int), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    bool success = false;
    __try {
        *reinterpret_cast<int*>(addr) = value;
        success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        success = false;
    }

    VirtualProtect((LPVOID)addr, sizeof(int), oldProtect, &oldProtect);
    return success;
}

void ForceGraphicsRefresh() {
    // Resize the window slightly
    HWND hwnd = FindWindowW(WINDOW_CLASS, nullptr);
    if (hwnd) {
        RECT rc;
        GetWindowRect(hwnd, &rc);
        SetWindowPos(hwnd, nullptr, rc.left, rc.top, rc.right - rc.left - 1,
            rc.bottom - rc.top, SWP_NOZORDER | SWP_FRAMECHANGED);
        SetWindowPos(hwnd, nullptr, rc.left, rc.top, rc.right - rc.left,
            rc.bottom - rc.top, SWP_NOZORDER | SWP_FRAMECHANGED);
        Log("  - Window resized to force refresh");
    }

    // Minimize/restore
    if (hwnd) {
        ShowWindow(hwnd, SW_MINIMIZE);
        ShowWindow(hwnd, SW_RESTORE);
        Log("  - Window minimized/restored");
    }

    // Send paint message
    if (hwnd) {
        InvalidateRect(hwnd, nullptr, TRUE);
        UpdateWindow(hwnd);
        Log("  - Sent WM_PAINT message");
    }

    // Alt-tab simulation
    keybd_event(VK_MENU, 0, 0, 0); // Alt key down
    keybd_event(VK_TAB, 0, 0, 0);  // Tab key down
    keybd_event(VK_TAB, 0, KEYEVENTF_KEYUP, 0);
    keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);
    Log("  - Sent Alt-Tab");
}

void TestCandidate(uintptr_t addr) {
    Log("Testing candidate: 0x%p", (void*)addr);

    int originalValue = SafeReadAddress(addr);
    if (originalValue == -1) {
        Log("  - Failed to read address");
        return;
    }

    if (originalValue != 0 && originalValue != 1) {
        Log("  - Value not boolean: %d", originalValue);
        return;
    }

    int newValue = originalValue ? 0 : 1;
    Log("  - Changing from %d to %d", originalValue, newValue);

    if (!SafeWriteAddress(addr, newValue)) {
        Log("  - Failed to write address");
        return;
    }

    // Verify write
    int currentValue = SafeReadAddress(addr);
    if (currentValue != newValue) {
        Log("  - Verification failed: expected %d, got %d", newValue, currentValue);
        return;
    }

    Log("  - Value changed successfully");

    // Force graphics refresh
    ForceGraphicsRefresh();

    // Leave the new value applied
    Log("  - New value left applied");
}

void ResizeWindow() {
    HWND hwnd = FindWindowW(WINDOW_CLASS, nullptr);
    if (!hwnd) {
        Log("Window not found");
        return;
    }

    // Get window style
    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);

    // Calculate size with borders
    RECT rc = { 0, 0, TARGET_WIDTH, TARGET_HEIGHT };
    AdjustWindowRectEx(&rc, style, FALSE, exStyle);

    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    // Center window
    int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

    // Resize
    SetWindowPos(hwnd, nullptr, x, y, width, height,
        SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);

    Log("Window resized to %dx%d", width, height);
}

void MainLoop() {
    logFile.open("PeggleHook.log", std::ios::out | std::ios::trunc);
    Log("==== Resolution Hook Started ====");

    // First resize the window
    ResizeWindow();
    Sleep(1000); // Give the game time to settle

    // Test all candidate addresses
    for (size_t i = 0; i < numCandidates; i++) {
        TestCandidate(candidateAddresses[i]);
        Log("--------------------------------------");
        Sleep(3000); // Pause between candidates
    }

    Log("==== All candidates tested ====");
    Log("Observe which change had the desired effect");

    // Keep the DLL loaded
    while (true) {
        Sleep(10000);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            MainLoop();
            return 0;
            }, nullptr, 0, nullptr);
    }
    return TRUE;
}