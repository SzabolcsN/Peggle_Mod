#include "pch.h"
#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <d3d9.h>
#include <detours.h>
#include <Psapi.h>

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Psapi.lib")

// Configuration
constexpr DWORD DESIRED_WIDTH = 1280;
constexpr DWORD DESIRED_HEIGHT = 960;
constexpr const wchar_t* WINDOW_CLASS = L"MainWindow";

// Global variables
std::ofstream logFile;
IDirect3DDevice9* pDevice = nullptr;
bool g_hooksInstalled = false;
static D3DPRESENT_PARAMETERS g_pp = {};
static bool g_viewportSet = false;

// Function prototypes
typedef HRESULT(APIENTRY* Present_t)(IDirect3DDevice9*, const RECT*, const RECT*, HWND, const RGNDATA*);
typedef HRESULT(APIENTRY* Reset_t)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);
typedef HRESULT(APIENTRY* CreateDevice_t)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS*, IDirect3DDevice9**);

typedef IDirect3D9* (WINAPI* Direct3DCreate9_t)(UINT);
static Direct3DCreate9_t True_Direct3DCreate9 = nullptr;
IDirect3D9* WINAPI Hooked_Direct3DCreate9(UINT);

// Original functions
Present_t OriginalPresent = nullptr;
Reset_t OriginalReset = nullptr;
CreateDevice_t OriginalCreateDevice = nullptr;

// Logging function
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

// Force window size and position
void ResizeGameWindow() {
    HWND hwnd = FindWindowW(WINDOW_CLASS, nullptr);
    if (!hwnd) {
        Log("Game window not found");
        return;
    }

    // Get window title for debugging
    wchar_t title[256] = L"";
    GetWindowTextW(hwnd, title, 256);
    Log("Resizing window: %ls", title);

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

    // ResizeGameWindow(), right after SetWindowPos:
    if (pDevice) {
        g_pp.BackBufferWidth = DESIRED_WIDTH;
        g_pp.BackBufferHeight = DESIRED_HEIGHT;
        g_pp.Windowed = TRUE;
        pDevice->Reset(&g_pp);
        Log("Forced Reset in ResizeGameWindow");
    }

    SendMessage(hwnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(DESIRED_WIDTH, DESIRED_HEIGHT));

    Log("Window resized to %dx%d", width, height);
}

// Direct3D hook to modify presentation parameters
HRESULT APIENTRY PresentHook(
    IDirect3DDevice9* device,
    const RECT* src, const RECT* dst,
    HWND hwndOverride,
    const RGNDATA* dirty)
{
    if (device && !g_viewportSet) {
        D3DVIEWPORT9 vp;
        vp.X = 0;
        vp.Y = 0;
        vp.Width = DESIRED_WIDTH;
        vp.Height = DESIRED_HEIGHT;
        vp.MinZ = 0.0f;
        vp.MaxZ = 1.0f;

        device->SetViewport(&vp);
        Log("Custom viewport applied %dx%d", vp.Width, vp.Height);
        g_viewportSet = true;
    }

    return OriginalPresent(device, src, dst, hwndOverride, dirty);
}

// Direct3D hook to handle device reset
HRESULT APIENTRY ResetHook(IDirect3DDevice9* pDevice,
    D3DPRESENT_PARAMETERS* pPresentationParameters) {
    Log("Reset called - modifying resolution");

    // Force desired resolution
    pPresentationParameters->BackBufferWidth = DESIRED_WIDTH;
    pPresentationParameters->BackBufferHeight = DESIRED_HEIGHT;
    pPresentationParameters->Windowed = TRUE;

    // Call original reset
    HRESULT hr = OriginalReset(pDevice, pPresentationParameters);
    if (SUCCEEDED(hr)) {
        Log("Resolution set to %dx%d", DESIRED_WIDTH, DESIRED_HEIGHT);
    }
    else {
        Log("Reset failed: 0x%X", hr);
    }
    return hr;
}

// Hook for device creation
HRESULT APIENTRY CreateDeviceHook(IDirect3D9* pD3D,
    UINT Adapter,
    D3DDEVTYPE DeviceType,
    HWND hFocusWindow,
    DWORD BehaviorFlags,
    D3DPRESENT_PARAMETERS* pPresentationParameters,
    IDirect3DDevice9** ppReturnedDeviceInterface) {
    Log("CreateDevice called - modifying resolution");

    // Force desired resolution
    pPresentationParameters->BackBufferWidth = DESIRED_WIDTH;
    pPresentationParameters->BackBufferHeight = DESIRED_HEIGHT;
    pPresentationParameters->Windowed = TRUE;

    g_pp = *pPresentationParameters;

    // Call original CreateDevice
    HRESULT hr = OriginalCreateDevice(pD3D, Adapter, DeviceType, hFocusWindow, BehaviorFlags,
        pPresentationParameters, ppReturnedDeviceInterface);

    if (SUCCEEDED(hr)) {
        Log("Device created at %dx%d", DESIRED_WIDTH, DESIRED_HEIGHT);

        // Get device function addresses
        void** pVTable = *reinterpret_cast<void***>(*ppReturnedDeviceInterface);
        OriginalReset = reinterpret_cast<Reset_t>(pVTable[16]);
        OriginalPresent = reinterpret_cast<Present_t>(pVTable[17]);
        pDevice = *ppReturnedDeviceInterface;

        // Prepare hooks
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        // Hook Reset and Present functions
        DetourAttach(&(PVOID&)OriginalReset, ResetHook);
        DetourAttach(&(PVOID&)OriginalPresent, PresentHook);

        if (DetourTransactionCommit() != NO_ERROR) {
            Log("Failed to attach device hooks");
        }
        else {
            Log("Device hooks installed");
            g_hooksInstalled = true;
        }
    }
    else {
        Log("CreateDevice failed: 0x%X", hr);
    }

    return hr;
}

// Hook Direct3D creation
void HookDirect3D() {
    // Get Direct3D9 interface
    IDirect3D9* pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (!pD3D) {
        Log("Failed to create D3D9 interface");
        return;
    }

    // Get vtable
    void** pVTable = *reinterpret_cast<void***>(pD3D);
    OriginalCreateDevice = reinterpret_cast<CreateDevice_t>(pVTable[16]); // CreateDevice is index 16

    // Prepare hooks
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OriginalCreateDevice, CreateDeviceHook);

    if (DetourTransactionCommit() != NO_ERROR) {
        Log("Failed to attach CreateDevice hook");
    }
    else {
        Log("CreateDevice hook installed");
    }

    pD3D->Release();
}

IDirect3D9* WINAPI Hooked_Direct3DCreate9(UINT SDKVersion) {
    // call the real one first
    IDirect3D9* pD3D = True_Direct3DCreate9(SDKVersion);
    if (pD3D) {
        // grab vtable pointer
        void** vtable = *reinterpret_cast<void***>(pD3D);
        // save the game's CreateDevice pointer
        OriginalCreateDevice = reinterpret_cast<CreateDevice_t>(vtable[16]);

        // detour it _right now_
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalCreateDevice, CreateDeviceHook);
        if (DetourTransactionCommit() == NO_ERROR) {
            Log("Successfully hooked IDirect3D9::CreateDevice");
        }
        else {
            Log("Failed to hook CreateDevice");
        }
    }
    return pD3D;
}


// Main initialization
void Initialize() {
    logFile.open("PeggleHook.log", std::ios::out | std::ios::trunc);
    Log("==== Peggle Resolution Hook Initialized ====");

    // Initial window resize
    ResizeGameWindow();

    // Install Direct3D hooks
    HookDirect3D();

    // Set up periodic resizing
    while (true) {
        ResizeGameWindow();
        Sleep(1000);
    }
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);

        // Grab the real d3d9.dll handle
        HMODULE hD3D9 = GetModuleHandleW(L"d3d9.dll");
        if (hD3D9) {
            True_Direct3DCreate9 = (Direct3DCreate9_t)
                GetProcAddress(hD3D9, "Direct3DCreate9");
        }
        if (True_Direct3DCreate9) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            // attach export‐level hook
            DetourAttach((PVOID*)&True_Direct3DCreate9,
                Hooked_Direct3DCreate9);
            DetourTransactionCommit();
            Log("Export hook on Direct3DCreate9 installed");
        }

        // Now start your resize thread
        CreateThread(nullptr, 0,
            [](LPVOID)->DWORD {
                Initialize();
                return 0;
            },
            nullptr, 0, nullptr);
    }
    break;

    case DLL_PROCESS_DETACH: {
        Log("DLL unloading, removing hooks…");

        // Detach the export‐level hook
        if (True_Direct3DCreate9) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach((PVOID*)&True_Direct3DCreate9,
                Hooked_Direct3DCreate9);
            DetourTransactionCommit();
        }

        // Detach device‐level hooks if installed
        if (g_hooksInstalled) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach((PVOID*)&OriginalCreateDevice, CreateDeviceHook);
            DetourDetach((PVOID*)&OriginalReset, ResetHook);
            DetourDetach((PVOID*)&OriginalPresent, PresentHook);
            DetourTransactionCommit();
        }

        if (logFile.is_open()) {
            logFile.close();
        }
    }
    break;
    }
    return TRUE;
}
