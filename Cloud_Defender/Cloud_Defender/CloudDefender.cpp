#undef UNICODE
#undef _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <ctime>
#include <thread>
#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")

std::vector<std::string> suspiciousProcesses = {
    "cheatengine.exe", "x32dbg.exe", "ollydbg.exe", "ida.exe",
    "ida64.exe", "dbgview.exe", "windbg.exe"
};

HANDLE mutexHandle;

std::string GetCurrentDateTime() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    localtime_s(&tstruct, &now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
}

void EncryptLog(std::string& log) {
    char key = 0x7A;
    for (char& c : log) {
        c ^= key;
    }
}

void LogToFile(const std::string& message) {
    std::ofstream logFile("CloudDefender_Log.txt", std::ios::app);
    if (logFile.is_open()) {
        std::string encryptedMessage = GetCurrentDateTime() + " - " + message;
        EncryptLog(encryptedMessage);
        logFile << encryptedMessage << "\n";
        logFile.close();
    }
}

void ProtectMemory() {
    DWORD oldProtect;
    VirtualProtect((LPVOID)GetModuleHandle(NULL), 0x1000, PAGE_READONLY, &oldProtect);
}

bool DetectHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            LogToFile("[DEBUG] Hardware breakpoint detectado!");
            return true;
        }
    }
    return false;
}

void DetectSuspiciousProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            for (const std::string& suspicious : suspiciousProcesses) {
                if (_stricmp(pe.szExeFile, suspicious.c_str()) == 0) {
                    std::string message = "[ALERT] Processo suspeito detectado: " + std::string(pe.szExeFile);
                    LogToFile(message);

                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                    }
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}

void MonitorProcesses() {
    while (true) {
        DetectSuspiciousProcesses();
        Sleep(3000);
    }
}

void Watchdog() {
    int restartAttempts = 0;
    const int maxAttempts = 3;

    while (true) {
        HWND hWnd = FindWindow(NULL, "Cloud Defender");
        if (!hWnd) {
            LogToFile("[ERROR] Processo encerrado!");

            if (restartAttempts < maxAttempts) {
                LogToFile("[INFO] Tentando reiniciar o processo...");
                restartAttempts++;
                ShellExecuteW(NULL, L"open", L"Cloud_Defender.exe", NULL, NULL, SW_SHOW);
                Sleep(5000);
            }
            else {
                LogToFile("[ERROR] Máximo de tentativas de reinício atingido.");
                break;
            }
        }

        Sleep(5000);
    }
}

int main() {
    mutexHandle = CreateMutex(NULL, TRUE, "CloudDefender_Mutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "Cloud Defender já está em execução!" << std::endl;
        return 1;
    }

    LogToFile("[INFO] Cloud Defender iniciado");

    ProtectMemory();

    std::thread watchdogThread(Watchdog);
    watchdogThread.detach();

    std::thread monitorThread(MonitorProcesses);
    monitorThread.detach();

    if (DetectHardwareBreakpoints()) {
        LogToFile("[DEBUG] Breakpoint de hardware detectado!");
    }

    system("pause");
    CloseHandle(mutexHandle);
    return 1;
}
