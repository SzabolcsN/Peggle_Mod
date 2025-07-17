#include "pch.h"
#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <detours.h>
#include <TlHelp32.h>
#include <fstream>
#include <Psapi.h>
#include <cstdarg>
#include <string>

constexpr DWORD DESIRED_WIDTH = 1280;
constexpr DWORD DESIRED_HEIGHT = 720;
constexpr const char* TARGET_PROCESS = "Peggle.exe";
constexpr const char* TARGET_CLASS = "PeggleClass";
constexpr DWORD MAX_WAIT_TIME = 10000;

std::ofstream logFile;
uintptr_t g_peggleBase = 0;
DWORD g_pegglePID = 0;

void Log(const char* format, ...) {
    if (!logFile.is_open()) return;

    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, sizeof(buffer), format, args);
    va_end(args);

    logFile << buffer << std::endl;
    logFile.flush();
}

DWORD FindPeggleProcess() {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        Log("CreateToolhelp32Snapshot failed: %d", GetLastError());
        return 0;
    }

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        Log("Process32First failed: %d", GetLastError());
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, TARGET_PROCESS) == 0) {
            g_pegglePID = pe32.th32ProcessID;
            Log("Found Peggle process: PID=%d", g_pegglePID);
            CloseHandle(hSnapshot);
            return g_pegglePID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    Log("Peggle process not found");
    return 0;
}

uintptr_t GetPeggleBaseAddress() {
    if (!g_pegglePID) return 0;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_pegglePID);
    if (!hProcess) {
        Log("OpenProcess failed: %d", GetLastError());
        return 0;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        char modName[MAX_PATH];
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            if (GetModuleFileNameExA(hProcess, hMods[i], modName, sizeof(modName))) {
                if (strstr(modName, TARGET_PROCESS)) {
                    g_peggleBase = (uintptr_t)hMods[i];
                    Log("Peggle base address: 0x%p", (void*)g_peggleBase);
                    CloseHandle(hProcess);
                    return g_peggleBase;
                }
            }
        }
    }
    else {
        Log("EnumProcessModules failed: %d", GetLastError());
    }

    CloseHandle(hProcess);
    return 0;
}

uintptr_t CalculatePeggleAddress(uintptr_t offset) {
    if (!g_peggleBase) {
        Log("Cannot calculate address: base not set");
        return 0;
    }

    // Adjust for ASLR: offset - default base (0x400000) + actual base
    uintptr_t actualAddr = g_peggleBase + (offset - 0x00400000);
    Log("Calculated address: 0x%p = 0x%p + (0x%p - 0x00400000)",
        (void*)actualAddr, (void*)g_peggleBase, (void*)offset);

    return actualAddr;
}

bool PatchMemory(uintptr_t address, uint32_t value) {
    if (!g_pegglePID) {
        Log("PatchMemory failed: no PID");
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, g_pegglePID);
    if (!hProcess) {
        Log("OpenProcess failed: %d", GetLastError());
        return false;
    }

    uint32_t originalValue = 0;
    SIZE_T bytesRead;
    if (ReadProcessMemory(hProcess, (LPCVOID)address, &originalValue, sizeof(originalValue), &bytesRead)) {
        Log("Original value at 0x%p: %d (0x%X)", (void*)address, originalValue, originalValue);
    }
    else {
        Log("ReadProcessMemory failed: %d", GetLastError());
    }

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, (LPVOID)address, sizeof(value), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        Log("VirtualProtectEx failed: %d", GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(value), &bytesWritten)) {
        Log("WriteProcessMemory failed: %d", GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    // Verify write
    uint32_t newValue = 0;
    if (ReadProcessMemory(hProcess, (LPCVOID)address, &newValue, sizeof(newValue), &bytesRead)) {
        Log("New value at 0x%p: %d (0x%X)", (void*)address, newValue, newValue);
    }

    VirtualProtectEx(hProcess, (LPVOID)address, sizeof(value), oldProtect, &oldProtect);
    CloseHandle(hProcess);

    if (newValue == value) {
        Log("Successfully patched 0x%p: %d -> %d", (void*)address, originalValue, value);
        return true;
    }

    Log("Patch verification failed");
    return false;
}

// Window management
void CenterGameWindow() {
    HWND hwnd = FindWindowA(TARGET_CLASS, NULL);
    if (!hwnd) {
        Log("Game window not found");
        return;
    }

    RECT rc;
    GetWindowRect(hwnd, &rc);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    int x = (screenWidth - DESIRED_WIDTH) / 2;
    int y = (screenHeight - DESIRED_HEIGHT) / 2;

    if (width != DESIRED_WIDTH || height != DESIRED_HEIGHT || rc.left != x || rc.top != y) {
        Log("Adjusting window: %dx%d -> %dx%d at (%d,%d)",
            width, height, DESIRED_WIDTH, DESIRED_HEIGHT, x, y);

        SetWindowPos(hwnd, NULL, x, y, DESIRED_WIDTH, DESIRED_HEIGHT,
            SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
    }
}

// Timer callback for window management
VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    CenterGameWindow();
}

void ApplyResolutionPatches() {
    // Get absolute addresses
    uintptr_t widthAddr = CalculatePeggleAddress(0x0055E034);
    uintptr_t heightAddr = CalculatePeggleAddress(0x0055E038);

    if (!widthAddr || !heightAddr) {
        Log("Failed to calculate addresses");
        return;
    }

    // Patch memory
    PatchMemory(widthAddr, DESIRED_WIDTH);
    PatchMemory(heightAddr, DESIRED_HEIGHT);

    // Set up periodic window centering
    SetTimer(NULL, 0, 1000, TimerProc);
}

DWORD WINAPI InitThread(LPVOID) {
    // Initialize logging
    logFile.open("PeggleResolutionHook.log", std::ios::out | std::ios::trunc);
    Log("==== Peggle Resolution Hook Initializing ====");

    // Wait for Peggle to launch
    DWORD startTime = GetTickCount();
    while (GetTickCount() - startTime < MAX_WAIT_TIME) {
        if (FindPeggleProcess() && GetPeggleBaseAddress()) {
            break;
        }
        Sleep(500);
    }

    if (!g_pegglePID || !g_peggleBase) {
        Log("Failed to locate Peggle process");
        return 0;
    }

    // Apply patches and set up window management
    ApplyResolutionPatches();

    Log("==== Hook Initialization Complete ====");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("DLL unloaded");
        if (logFile.is_open()) logFile.close();
    }
    return TRUE;
}