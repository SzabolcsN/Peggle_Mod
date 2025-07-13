#include "pch.h"
#include <Windows.h>
#include <ddraw.h>
#include <shlwapi.h>
#include <fstream>
#include <ctime>

// Define IID_IDirectDraw7
const GUID IID_IDirectDraw7 = {
    0x15e65ec0, 0x3b9c, 0x11d2,
    {0xb9, 0x2f, 0x00, 0x60, 0x97, 0x97, 0xea, 0x5b}
};

#pragma comment(lib, "shlwapi.lib")

UINT g_TargetWidth = 1280;
UINT g_TargetHeight = 720;
bool g_Enabled = true;

std::ofstream g_LogFile;

void InitializeLog() {
    char logPath[MAX_PATH];
    GetModuleFileNameA(nullptr, logPath, MAX_PATH);
    PathRemoveFileSpecA(logPath);
    PathCombineA(logPath, logPath, "PeggleResolution.log");
    g_LogFile.open(logPath, std::ios::out | std::ios::trunc);
}

void Log(const char* format, ...) {
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

// Load settings from INI file
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

typedef HRESULT(WINAPI* DirectDrawCreate_t)(GUID*, LPDIRECTDRAW*, IUnknown*);
typedef HRESULT(WINAPI* DirectDrawCreateEx_t)(GUID*, LPVOID*, REFIID, IUnknown*);
typedef HRESULT(STDMETHODCALLTYPE* SetDisplayMode_t)(LPDIRECTDRAW7, DWORD, DWORD, DWORD);

DirectDrawCreate_t Real_DirectDrawCreate = nullptr;
DirectDrawCreateEx_t Real_DirectDrawCreateEx = nullptr;
SetDisplayMode_t Original_SetDisplayMode = nullptr;

// Hooked SetDisplayMode
HRESULT STDMETHODCALLTYPE Hooked_SetDisplayMode(
    LPDIRECTDRAW7 pDD,
    DWORD width,
    DWORD height,
    DWORD bpp
) {
    Log("SetDisplayMode called: %dx%d", width, height);

    if (g_Enabled) {
        Log("Overriding resolution to %dx%d", g_TargetWidth, g_TargetHeight);

        // Set the new resolution
        HRESULT hr = Original_SetDisplayMode(pDD, g_TargetWidth, g_TargetHeight, bpp);

        // Resize window
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

// Hooked DirectDrawCreate
HRESULT WINAPI DirectDrawCreate(
    GUID* lpGUID,
    LPDIRECTDRAW* lplpDD,
    IUnknown* pUnkOuter
) {
    Log("DirectDrawCreate called");

    if (!Real_DirectDrawCreate) {
        HMODULE realDDraw = LoadLibraryA("ddraw_real.dll");
        if (realDDraw) {
            Real_DirectDrawCreate = (DirectDrawCreate_t)GetProcAddress(realDDraw, "DirectDrawCreate");
        }
    }

    if (!Real_DirectDrawCreate) {
        Log("Failed to load real DirectDrawCreate");
        return DDERR_GENERIC;
    }

    HRESULT hr = Real_DirectDrawCreate(lpGUID, lplpDD, pUnkOuter);
    if (FAILED(hr)) {
        Log("DirectDrawCreate failed: 0x%X", hr);
        return hr;
    }

    // Query for DirectDraw7 interface
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

HRESULT WINAPI DirectDrawCreateEx(
    GUID* lpGUID,
    LPVOID* lplpDD,
    REFIID iid,
    IUnknown* pUnkOuter
) {
    Log("DirectDrawCreateEx called");

    if (!Real_DirectDrawCreateEx) {
        HMODULE realDDraw = LoadLibraryA("ddraw_real.dll");
        if (realDDraw) {
            Real_DirectDrawCreateEx = (DirectDrawCreateEx_t)GetProcAddress(realDDraw, "DirectDrawCreateEx");
        }
    }

    if (!Real_DirectDrawCreateEx) {
        Log("Failed to load real DirectDrawCreateEx");
        return DDERR_GENERIC;
    }

    return Real_DirectDrawCreateEx(lpGUID, lplpDD, iid, pUnkOuter);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeLog();
        Log("ddraw.dll proxy loaded");
        LoadConfig();
    }
    return TRUE;
}