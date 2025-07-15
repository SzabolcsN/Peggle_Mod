#include "pch.h"
#include <Windows.h>
#include <detours.h>

const UINT32 TARGET_WIDTH = 1280;
const UINT32 TARGET_HEIGHT = 720;
const char* TARGET_WINDOW_CLASS = "PopcapWindowClass";

typedef HWND(WINAPI* CreateWindowExA_t)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
typedef BOOL(WINAPI* SetWindowPos_t)(HWND, HWND, int, int, int, int, UINT);
typedef BOOL(WINAPI* AdjustWindowRect_t)(LPRECT, DWORD, BOOL);

CreateWindowExA_t Original_CreateWindowExA = nullptr;
SetWindowPos_t Original_SetWindowPos = nullptr;
AdjustWindowRect_t Original_AdjustWindowRect = nullptr;
bool g_ResolutionSet = false;

BOOL WINAPI Hooked_AdjustWindowRect(LPRECT lpRect, DWORD dwStyle, BOOL bMenu) {
    if (g_ResolutionSet && lpRect) {
        lpRect->right = TARGET_WIDTH + (lpRect->right - lpRect->left);
        lpRect->bottom = TARGET_HEIGHT + (lpRect->bottom - lpRect->top);
        return TRUE;
    }
    return Original_AdjustWindowRect(lpRect, dwStyle, bMenu);
}

BOOL WINAPI Hooked_SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags) {
    char className[256];
    if (GetClassNameA(hWnd, className, sizeof(className))) {
        if (strcmp(className, TARGET_WINDOW_CLASS) == 0) {
            // Force target resolution
            cx = TARGET_WIDTH;
            cy = TARGET_HEIGHT;

            // Center window
                X = (GetSystemMetrics(SM_CXSCREEN) - cx) / 2;
                Y = (GetSystemMetrics(SM_CYSCREEN) - cy) / 2;

                g_ResolutionSet = true;
        }
    }
    return Original_SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
}

// Hooked CreateWindowExA
HWND WINAPI Hooked_CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle,
    int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
    HINSTANCE hInstance, LPVOID lpParam) {
    if (lpClassName && strcmp(lpClassName, TARGET_WINDOW_CLASS) == 0) {
        // Force target resolution
        nWidth = TARGET_WIDTH;
        nHeight = TARGET_HEIGHT;

        // Center window
        X = (GetSystemMetrics(SM_CXSCREEN) - nWidth) / 2;
        Y = (GetSystemMetrics(SM_CYSCREEN) - nHeight) / 2;

        g_ResolutionSet = true;
    }
    return Original_CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle,
        X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

void InstallHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    HMODULE user32 = GetModuleHandleA("user32.dll");
    if (user32) {
        Original_AdjustWindowRect = (AdjustWindowRect_t)GetProcAddress(user32, "AdjustWindowRect");
        Original_CreateWindowExA = (CreateWindowExA_t)GetProcAddress(user32, "CreateWindowExA");
        Original_SetWindowPos = (SetWindowPos_t)GetProcAddress(user32, "SetWindowPos");

        if (Original_AdjustWindowRect) DetourAttach((PVOID*)&Original_AdjustWindowRect, Hooked_AdjustWindowRect);
        if (Original_CreateWindowExA) DetourAttach((PVOID*)&Original_CreateWindowExA, Hooked_CreateWindowExA);
        if (Original_SetWindowPos) DetourAttach((PVOID*)&Original_SetWindowPos, Hooked_SetWindowPos);
    }

    DetourTransactionCommit();
}

// Initialization thread
DWORD WINAPI InitThread(LPVOID) {
    for (int i = 0; i < 50; i++) {
        if (GetModuleHandleA("user32.dll")) break;
        Sleep(100);
    }
    InstallHooks();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    }
    return TRUE;
}