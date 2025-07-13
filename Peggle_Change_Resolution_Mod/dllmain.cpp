#include "pch.h"
#include <Windows.h>
#include <ddraw.h>
#include <shlwapi.h>
#include <detours.h>
#include <fstream>
#include <ctime>

const GUID IID_IDirectDraw7 = {
    0x15e65ec0, 0x3b9c, 0x11d2,
    {0xb9, 0x2f, 0x00, 0x60, 0x97, 0x97, 0xea, 0x5b}
};

#pragma comment(lib, "ddraw.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "detours.lib")

UINT g_TargetWidth = 1280;
UINT g_TargetHeight = 720;
bool g_Enabled = true;

std::ofstream g_LogFile;
bool g_LogInitialized = false;

void InitializeLog() {
    if (g_LogInitialized) return;

    char logPath[MAX_PATH];
    GetModuleFileNameA(nullptr, logPath, MAX_PATH);
    PathRemoveFileSpecA(logPath);
    PathCombineA(logPath, logPath, "PeggleResolution.log");

    g_LogFile.open(logPath, std::ios::out | std::ios::trunc);
    if (g_LogFile.is_open()) {
        time_t now = time(nullptr);
        char timeStr[26];
        ctime_s(timeStr, sizeof(timeStr), &now);
        g_LogFile << "===== Log Started: " << timeStr;
        g_LogFile.flush();
        g_LogInitialized = true;
    }
}

void Log(const char* format, ...) {
    if (!g_LogInitialized) InitializeLog();
    if (!g_LogFile.is_open()) return;

    char buffer[512];
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, sizeof(buffer), format, args);
    va_end(args);

    g_LogFile << buffer << std::endl;
    g_LogFile.flush();
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
}

typedef HRESULT(WINAPI* DirectDrawCreate_t)(GUID*, LPDIRECTDRAW*, IUnknown*);
typedef HRESULT(STDMETHODCALLTYPE* SetDisplayMode_t)(LPDIRECTDRAW7, DWORD, DWORD, DWORD);

DirectDrawCreate_t Original_DirectDrawCreate = nullptr;
SetDisplayMode_t Original_SetDisplayMode = nullptr;

void LoadConfig() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    PathRemoveFileSpecA(path);
    PathCombineA(path, path, "PeggleResolution.ini");

    g_TargetWidth = GetPrivateProfileIntA("Settings", "Width", 1280, path);
    g_TargetHeight = GetPrivateProfileIntA("Settings", "Height", 720, path);
    g_Enabled = GetPrivateProfileIntA("Settings", "Enabled", 1, path) != 0;

    Log("Config loaded: %dx%d, Enabled=%d", g_TargetWidth, g_TargetHeight, g_Enabled);
}

HRESULT STDMETHODCALLTYPE Hooked_SetDisplayMode(
    LPDIRECTDRAW7 pDD,
    DWORD width,
    DWORD height,
    DWORD bpp
) {
    Log("SetDisplayMode called: %dx%d", width, height);

    if (g_Enabled) {
        Log("Overriding resolution to %dx%d", g_TargetWidth, g_TargetHeight);

        HRESULT hr = Original_SetDisplayMode(pDD, g_TargetWidth, g_TargetHeight, bpp);

        HWND hwnd = GetForegroundWindow();
        if (hwnd) {
            SetWindowPos(hwnd, NULL, 0, 0, g_TargetWidth, g_TargetHeight,
                SWP_NOZORDER | SWP_NOACTIVATE);
            Log("Window resized manually");
        }

        return hr;
    }

    return Original_SetDisplayMode(pDD, width, height, bpp);
}

HRESULT WINAPI Hooked_DirectDrawCreate(
    GUID* lpGUID,
    LPDIRECTDRAW* lplpDD,
    IUnknown* pUnkOuter
) {
    Log("DirectDrawCreate called");

    HRESULT hr = Original_DirectDrawCreate(lpGUID, lplpDD, pUnkOuter);
    if (FAILED(hr)) {
        Log("DirectDrawCreate failed: 0x%X", hr);
        return hr;
    }

    LPDIRECTDRAW7 pDD7 = nullptr;
    hr = (*lplpDD)->QueryInterface(IID_IDirectDraw7, (LPVOID*)&pDD7);
    if (FAILED(hr)) {
        Log("QueryInterface failed: 0x%X", hr);
        return hr;
    }

    Log("Obtained IDirectDraw7 interface");

    void** vTable = *(void***)pDD7;

    Original_SetDisplayMode = (SetDisplayMode_t)vTable[13];

    DWORD oldProtect;
    VirtualProtect(&vTable[13], sizeof(void*), PAGE_READWRITE, &oldProtect);
    vTable[13] = &Hooked_SetDisplayMode;
    VirtualProtect(&vTable[13], sizeof(void*), oldProtect, &oldProtect);

    Log("Hooked SetDisplayMode");

    pDD7->Release();

    return hr;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        InitializeLog();
        Log("DLL attached to process");
        LoadConfig();

        if (g_Enabled) {
            Log("Initializing DirectDraw hooks...");

            // Load ddraw.dll
            HMODULE ddraw = LoadLibraryA("ddraw.dll");
            if (!ddraw) {
                Log("Failed to load ddraw.dll");
                break;
            }

            Log("ddraw.dll loaded at 0x%p", ddraw);

            // Get DirectDrawCreate address
            Original_DirectDrawCreate = (DirectDrawCreate_t)GetProcAddress(ddraw, "DirectDrawCreate");
            if (!Original_DirectDrawCreate) {
                Log("GetProcAddress failed");
                break;
            }

            Log("Hooking DirectDrawCreate...");

            // Start hook transaction
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());

            // Attach hook
            if (DetourAttach(&(PVOID&)Original_DirectDrawCreate, Hooked_DirectDrawCreate) != NO_ERROR) {
                Log("DetourAttach failed");
                DetourTransactionAbort();
                break;
            }

            // Commit transaction
            if (DetourTransactionCommit() != NO_ERROR) {
                Log("DetourTransactionCommit failed");
                break;
            }

            Log("DirectDraw hook installed successfully");
        }
        break;

    case DLL_PROCESS_DETACH:
        Log("DLL detached from process");

        if (Original_DirectDrawCreate) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)Original_DirectDrawCreate, Hooked_DirectDrawCreate);
            DetourTransactionCommit();
        }

        if (g_LogFile.is_open()) {
            g_LogFile.close();
        }
        break;
    }
    return TRUE;
}