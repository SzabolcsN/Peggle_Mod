#include "pch.h"
#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <d3d9.h>
#include <detours.h>
#include <Psapi.h>
#include <vector>
#include <TlHelp32.h>
#include <winnt.h>
#include <shlwapi.h>

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// Configuration
constexpr DWORD TARGET_WIDTH = 1280;
constexpr DWORD TARGET_HEIGHT = 720;
constexpr const wchar_t* WINDOW_CLASS = L"MainWindow";
constexpr DWORD DESIRED_3D_SETTING = 1; // 1 = 3D acceleration enabled
constexpr int MAX_CANDIDATES_TO_TEST = 10000; // Limit to prevent infinite scanning

// Global variables
std::ofstream logFile;
IDirect3DDevice9* pDevice = nullptr;
bool g_hooksInstalled = false;
uintptr_t g_3dSettingAddr = 0;
uintptr_t g_applySettingsFunc = 0;
bool g_resolutionForced = false;
bool g_scanActive = true;
int g_candidateTestCount = 0;

// Function prototypes
typedef HRESULT(APIENTRY* Present_t)(IDirect3DDevice9*, const RECT*, const RECT*, HWND, const RGNDATA*);
typedef HRESULT(APIENTRY* Reset_t)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);
typedef HRESULT(APIENTRY* CreateDevice_t)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS*, IDirect3DDevice9**);
typedef void(__cdecl* ApplySettings_t)();

// Original functions
Present_t OriginalPresent = nullptr;
Reset_t OriginalReset = nullptr;
CreateDevice_t OriginalCreateDevice = nullptr;


// Logging System
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


// Window Management
void ResizeGameWindow() {
    HWND hwnd = FindWindowW(WINDOW_CLASS, nullptr);
    if (!hwnd) {
        Log("Window not found");
        return;
    }

    // Get window style
    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);

    // Calculate window size
    RECT rc = { 0, 0, TARGET_WIDTH, TARGET_HEIGHT };
    AdjustWindowRectEx(&rc, style, FALSE, exStyle);

    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    // Center window
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int x = (screenWidth - width) / 2;
    int y = (screenHeight - height) / 2;

    SetWindowPos(hwnd, nullptr, x, y, width, height,
        SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);

    Log("Window resized to %dx%d", width, height);
}


// Pattern Scanning
uintptr_t FindPattern(const char* module, const char* pattern, const char* mask) {
    MODULEINFO modInfo = { 0 };
    HMODULE hModule = GetModuleHandleA(module);

    if (!hModule || !GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        Log("FindPattern: Module not found");
        return 0;
    }

    uintptr_t base = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    uintptr_t size = modInfo.SizeOfImage;
    size_t patternLength = strlen(mask);

    for (uintptr_t i = 0; i < size - patternLength; i++) {
        bool found = true;

        for (size_t j = 0; j < patternLength; j++) {
            if (mask[j] != '?' && pattern[j] != *reinterpret_cast<char*>(base + i + j)) {
                found = false;
                break;
            }
        }

        if (found) {
            return base + i;
        }
    }

    return 0;
}


// PE Section Scanner
std::vector<uintptr_t> Find3DSettingCandidates() {
    std::vector<uintptr_t> candidates;
    HMODULE hModule = GetModuleHandle(nullptr);

    if (!hModule) {
        Log("GetModuleHandle failed");
        return candidates;
    }

    // Get PE header information
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        Log("Invalid DOS header");
        return candidates;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        Log("Invalid NT header");
        return candidates;
    }

    // Get section headers
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, section->Name, 8);

        // Only scan writable data sections
        if (strcmp(sectionName, ".data") != 0 &&
            strcmp(sectionName, ".rdata") != 0 &&
            strcmp(sectionName, ".bss") != 0) {
            continue;
        }

        uintptr_t start = reinterpret_cast<uintptr_t>(hModule) + section->VirtualAddress;
        uintptr_t end = start + section->Misc.VirtualSize;

        Log("Scanning section %s: 0x%p to 0x%p", sectionName, start, end);

        // Scan this section
        for (uintptr_t addr = start; addr < end - sizeof(DWORD); addr += sizeof(DWORD)) {
            if (!g_scanActive) break;

            // Only consider aligned addresses
            if (addr % 4 != 0) continue;

            // Skip obviously invalid addresses
            if (addr < 0x00400000 || addr > 0x7FFFFFFF) continue;

            // Check if readable
            if (IsBadReadPtr(reinterpret_cast<void*>(addr), sizeof(DWORD))) continue;

                DWORD value = *reinterpret_cast<DWORD*>(addr);
                if (value == 0 || value == 1) {
                    candidates.push_back(addr);
                }
        }
    }

    Log("Found %d candidate addresses in data sections", candidates.size());
        return candidates;
}


// Apply Settings Detection
void FindApplySettingsFunction() {
    // More specific patterns for ApplySettings function
    const char* patterns[] = {
        "\x83\xC4\x10\x85\xC0\x74\x0D",  // Common setting apply pattern
        "\x55\x8B\xEC\x83\xEC\x20",       // Function prologue
        "\x8B\x45\x08\x85\xC0\x74\x0A",   // Parameter check
        "\x6A\x01\xE8\x00\x00\x00\x00\x83\xC4\x04"  // Call pattern
    };

    const char* masks[] = {
        "xxxxxxx",
        "xxxxxx",
        "xxxxxxx",
        "xx????xxxx"
    };

    for (int i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        g_applySettingsFunc = FindPattern("Peggle.exe", patterns[i], masks[i]);
        if (g_applySettingsFunc) {
            Log("ApplySettings function found at 0x%p (Pattern %d)", g_applySettingsFunc, i);
            return;
        }
    }

    Log("ApplySettings function not found");
}


// 3D Setting Modification
bool Set3DAcceleration(DWORD value) {
    if (!g_3dSettingAddr) return false;

    // Validate address range
    if (g_3dSettingAddr < 0x00400000 || g_3dSettingAddr > 0x7FFFFFFF) {
        Log("Suspicious address 0x%p skipped", g_3dSettingAddr);
        return false;
    }

    // Check memory protection
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(g_3dSettingAddr), &mbi, sizeof(mbi))) {
        Log("VirtualQuery failed for 0x%p", g_3dSettingAddr);
        return false;
    }

    // Skip non-writable regions
    if (!(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE))) {
        Log("Address 0x%p not writable (Protection: 0x%X)", g_3dSettingAddr, mbi.Protect);
        return false;
    }

    DWORD oldProtect;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(g_3dSettingAddr), sizeof(DWORD),
        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        Log("VirtualProtect failed (0x%X)", GetLastError());
        return false;
    }

    DWORD originalValue = *reinterpret_cast<DWORD*>(g_3dSettingAddr);
    *reinterpret_cast<DWORD*>(g_3dSettingAddr) = value;
    VirtualProtect(reinterpret_cast<LPVOID>(g_3dSettingAddr), sizeof(DWORD), oldProtect, &oldProtect);

    Log("3D setting changed: 0x%p: %d -> %d", g_3dSettingAddr, originalValue, value);
    return true;
}


// DirectX Hooks
HRESULT APIENTRY ResetHook(IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* pParams) {
    Log("ResetHook called");

    // Force desired resolution
    pParams->BackBufferWidth = TARGET_WIDTH;
    pParams->BackBufferHeight = TARGET_HEIGHT;
    pParams->Windowed = TRUE;

    HRESULT hr = OriginalReset(pDevice, pParams);
    if (SUCCEEDED(hr)) {
        Log("Resolution forced to %dx%d", TARGET_WIDTH, TARGET_HEIGHT);
    }
    else {
        Log("Reset failed: 0x%X", hr);
    }
    return hr;
}

HRESULT APIENTRY CreateDeviceHook(IDirect3D9* pD3D, UINT Adapter, D3DDEVTYPE DeviceType, HWND hFocusWindow,
    DWORD BehaviorFlags, D3DPRESENT_PARAMETERS* pParams, IDirect3DDevice9** ppDevice) {
    Log("CreateDeviceHook called");

    // Force desired resolution
    pParams->BackBufferWidth = TARGET_WIDTH;
    pParams->BackBufferHeight = TARGET_HEIGHT;
    pParams->Windowed = TRUE;

    HRESULT hr = OriginalCreateDevice(pD3D, Adapter, DeviceType, hFocusWindow, BehaviorFlags, pParams, ppDevice);
    if (SUCCEEDED(hr)) {
        Log("Device created at %dx%d", TARGET_WIDTH, TARGET_HEIGHT);
        pDevice = *ppDevice;

        // Get device function addresses
        void** pVTable = *reinterpret_cast<void***>(*ppDevice);
        OriginalReset = reinterpret_cast<Reset_t>(pVTable[16]);

        // Install hooks
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalReset, ResetHook);
        DetourTransactionCommit();

        g_hooksInstalled = true;
    }
    return hr;
}

void HookDirect3D() {
    IDirect3D9* pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (!pD3D) {
        Log("Direct3DCreate9 failed");
        return;
    }

    void** pVTable = *reinterpret_cast<void***>(pD3D);
    OriginalCreateDevice = reinterpret_cast<CreateDevice_t>(pVTable[16]);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OriginalCreateDevice, CreateDeviceHook);
    DetourTransactionCommit();

    pD3D->Release();
    Log("Direct3D hooks installed");
}


// Testing & Validation
bool TestVisualChange() {
    // Check if backbuffer matches target resolution
    if (!pDevice) return false;

    D3DSURFACE_DESC desc;
    IDirect3DSurface9* backBuffer = nullptr;

    if (SUCCEEDED(pDevice->GetBackBuffer(0, 0, D3DBACKBUFFER_TYPE_MONO, &backBuffer))) {
        backBuffer->GetDesc(&desc);
        backBuffer->Release();

        if (desc.Width == TARGET_WIDTH && desc.Height == TARGET_HEIGHT) {
            Log("Resolution change verified: %dx%d", desc.Width, desc.Height);
            return true;
        }
    }
    return false;
}

void TestCandidateAddress(uintptr_t addr) {
    g_candidateTestCount++;

    // Only log every 100th test to avoid flooding
    if (g_candidateTestCount % 100 == 0) {
        Log("Testing candidate %d: 0x%p", g_candidateTestCount, addr);
    }

    g_3dSettingAddr = addr;

    // Skip non-boolean values
    DWORD originalValue = *reinterpret_cast<DWORD*>(addr);
    if (originalValue != 0 && originalValue != 1) return;

    // Toggle the value
    DWORD newValue = originalValue == 0 ? 1 : 0;

    if (Set3DAcceleration(newValue)) {
        // Apply settings if we found the function
        if (g_applySettingsFunc) {
            Log("Calling ApplySettings function");
            reinterpret_cast<ApplySettings_t>(g_applySettingsFunc)();
        }

        Sleep(500); // Allow time for rendering

        // Check if the setting persisted and resolution changed
        DWORD currentValue = *reinterpret_cast<DWORD*>(addr);
        bool visualChange = TestVisualChange();

        if (currentValue == newValue && visualChange) {
            Log("SUCCESS: Validated candidate 0x%p", addr);
            Set3DAcceleration(DESIRED_3D_SETTING);
            g_resolutionForced = true;
            g_scanActive = false;
            return;
        }

        // Restore original value
        Set3DAcceleration(originalValue);
    }
}


// Address Configuration
void SaveWorkingAddress(uintptr_t addr) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\PeggleHook", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "3DSettingAddress", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&addr), sizeof(addr));
        RegCloseKey(hKey);
        Log("Saved address 0x%p to registry", addr);
    }
}

uintptr_t LoadWorkingAddress() {
    HKEY hKey;
    uintptr_t addr = 0;
    DWORD size = sizeof(addr);

    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\PeggleHook", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "3DSettingAddress", NULL, NULL, reinterpret_cast<LPBYTE>(&addr), &size);
        RegCloseKey(hKey);
    }

    if (addr != 0) {
        Log("Loaded address 0x%p from registry", addr);
    }

    return addr;
}


// Main Functionality
void ForceResolution() {
    // 1. Apply 3D setting if we have it
    if (g_3dSettingAddr) {
        Set3DAcceleration(DESIRED_3D_SETTING);

        // Call apply function if available
        if (g_applySettingsFunc) {
            reinterpret_cast<ApplySettings_t>(g_applySettingsFunc)();
        }
    }

    // 2. Resize window (always do this)
    ResizeGameWindow();

    // 3. Flag as completed
    g_resolutionForced = true;
    Log("Resolution forcing completed");
}

DWORD WINAPI MemoryScannerThread(LPVOID) {
    Log("Starting targeted memory scan");

    // 1. Try registry address first
    uintptr_t regAddr = LoadWorkingAddress();
    if (regAddr) {
        Log("Testing registry address 0x%p", regAddr);
        TestCandidateAddress(regAddr);
        if (g_resolutionForced) return 0;
    }

    // 2. Try known working addresses
    const uintptr_t knownAddresses[] = {
        0x68D572C0, 0x03A17C48, 0x03A18C90,
        0x04B2F1A0, 0x04C3A8D0, 0x05D4B210,
        0x06E5C550, 0x07F6D890, 0x0899A1C0
    };

    for (uintptr_t addr : knownAddresses) {
        if (!g_scanActive) break;
        if (IsBadReadPtr(reinterpret_cast<void*>(addr), sizeof(DWORD))) continue;

        Log("Testing known address 0x%p", addr);
        TestCandidateAddress(addr);
        if (g_resolutionForced) {
            SaveWorkingAddress(addr);
            return 0;
        }
    }

    // 3. Find ApplySettings function
    FindApplySettingsFunction();

    // 4. Scan data sections for candidates
    std::vector<uintptr_t> candidates = Find3DSettingCandidates();
    for (uintptr_t addr : candidates) {
        if (!g_scanActive) break;
        if (g_candidateTestCount >= MAX_CANDIDATES_TO_TEST) {
            Log("Reached maximum candidate test limit");
            break;
        }
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
            Log("Scan aborted by user");
            break;
        }
        TestCandidateAddress(addr);
        if (g_resolutionForced) {
            SaveWorkingAddress(addr);
            break;
        }
    }

    if (!g_resolutionForced) {
        Log("Failed to find valid 3D setting address");
    }

    return 0;
}


// Initialization
void Initialize() {
    // Open log file
    logFile.open("PeggleHook.log", std::ios::out | std::ios::trunc);
    Log("==== Peggle Resolution Hook Initialized ====");
    Log("Target Resolution: %dx%d", TARGET_WIDTH, TARGET_HEIGHT);

    // Initial window resize
    ResizeGameWindow();

    // Install Direct3D hooks
    HookDirect3D();

    // Start memory scanner
    CreateThread(nullptr, 0, MemoryScannerThread, nullptr, 0, nullptr);
}


// DLL Entry Point
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
        g_scanActive = false;

        // Remove hooks
        if (g_hooksInstalled) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)OriginalReset, ResetHook);
            DetourDetach(&(PVOID&)OriginalCreateDevice, CreateDeviceHook);
            DetourTransactionCommit();
            Log("DirectX hooks removed");
        }

        if (logFile.is_open()) logFile.close();
    }
    return TRUE;
}