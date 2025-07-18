#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

int main() {
    // Use wide strings for Unicode compatibility
    const wchar_t* dllPath = L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\Peggle Deluxe\\PeggleResolutionHookStandalone.dll";
    const wchar_t* processName = L"Peggle.exe";

    // Find process ID
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32FirstW(snapshot, &entry)) {
        while (Process32NextW(snapshot, &entry)) {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                if (!hProcess) {
                    std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
                    continue;
                }

                // Calculate required memory size
                size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);

                // Allocate memory for DLL path
                LPVOID pathAddr = VirtualAllocEx(hProcess, NULL, pathSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!pathAddr) {
                    std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
                    CloseHandle(hProcess);
                    continue;
                }

                // Write DLL path
                if (!WriteProcessMemory(hProcess, pathAddr, dllPath, pathSize, NULL)) {
                    std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
                    VirtualFreeEx(hProcess, pathAddr, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                    continue;
                }

                // Get LoadLibrary address (Unicode version)
                LPTHREAD_START_ROUTINE loadLib = (LPTHREAD_START_ROUTINE)
                    GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

                // Create remote thread
                HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLib, pathAddr, 0, NULL);
                if (!hThread) {
                    std::cerr << "CreateRemoteThread failed: " << GetLastError() << std::endl;
                }
                else {
                    WaitForSingleObject(hThread, INFINITE);
                    CloseHandle(hThread);
                }

                // Clean up
                VirtualFreeEx(hProcess, pathAddr, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                break;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}