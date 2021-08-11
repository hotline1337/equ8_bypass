/**
 *
 * Title: EQU8 User-Mode Bypass and Injector
 * Author: hotline
 *
*/
#pragma once
#include <iostream>
#include <codecvt>
#include <string>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

inline auto EnablePrivilege(string privilegeName) -> void
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return;

	LUID luid;
	if (!LookupPrivilegeValueA(nullptr, privilegeName.c_str(), &luid))
	{
		CloseHandle(hToken);
		return;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		CloseHandle(hToken);
		return;
	}

	CloseHandle(hToken);
}

inline auto s2ws(const std::string& s) -> std::wstring
{
	const int slength = static_cast<int>(s.length()) + 1;
	const int len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	return r;
}

inline auto GetProcessIdByName(string processName) -> DWORD
{
	HANDLE hSnapshot;
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	DWORD pid = -1;
	PROCESSENTRY32 pe;
	ZeroMemory(&pe, sizeof(PROCESSENTRY32));
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &pe))
	{
		while (Process32Next(hSnapshot, &pe))
		{
			if (pe.szExeFile == processName)
			{
				pid = pe.th32ProcessID;
				break;
			}
		}
	}
	else
	{
		CloseHandle(hSnapshot);
		return 0;
	}

	if (pid == -1)
	{
		CloseHandle(hSnapshot);
		return 0;
	}

	CloseHandle(hSnapshot);
	return pid;
}

inline auto ImpersonateSystem() -> void
{
	const auto systemPid = GetProcessIdByName("winlogon.exe");
	HANDLE hSystemProcess;
	if ((hSystemProcess = OpenProcess(
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
		FALSE,
		systemPid)) == nullptr)
	{
		return;
	}

	HANDLE hSystemToken;
	if (!OpenProcessToken(
		hSystemProcess,
		MAXIMUM_ALLOWED,
		&hSystemToken))
	{
		CloseHandle(hSystemProcess);
		return;
	}

	HANDLE hDupToken;
	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = nullptr;
	tokenAttributes.bInheritHandle = FALSE;
	if (!DuplicateTokenEx(
		hSystemToken,
		MAXIMUM_ALLOWED,
		&tokenAttributes,
		SecurityImpersonation,
		TokenImpersonation,
		&hDupToken))
	{
		CloseHandle(hSystemToken);
		return;
	}

	if (!ImpersonateLoggedOnUser(hDupToken))
	{
		CloseHandle(hDupToken);
		CloseHandle(hSystemToken);
		return;
	}

	CloseHandle(hDupToken);
	CloseHandle(hSystemToken);
}

inline auto StartTrustedInstallerService() -> int
{
	SC_HANDLE hSCManager;
	if ((hSCManager = OpenSCManagerA(
		nullptr,
		SERVICES_ACTIVE_DATABASE,
		GENERIC_EXECUTE)) == nullptr)
	{
		return 0;
	}

	SC_HANDLE hService;
	if ((hService = OpenServiceA(
		hSCManager,
		"TrustedInstaller",
		GENERIC_READ | GENERIC_EXECUTE)) == nullptr)
	{
		CloseServiceHandle(hSCManager);
		return 0;
	}

	SERVICE_STATUS_PROCESS statusBuffer;
	DWORD bytesNeeded;
	while (QueryServiceStatusEx(
		hService,
		SC_STATUS_PROCESS_INFO,
		reinterpret_cast<LPBYTE>(&statusBuffer),
		sizeof(SERVICE_STATUS_PROCESS),
		&bytesNeeded))
	{
		if (statusBuffer.dwCurrentState == SERVICE_STOPPED)
		{
			if (!StartServiceA(hService, 0, nullptr))
			{
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCManager);
				return 0;
			}
		}
		if (statusBuffer.dwCurrentState == SERVICE_START_PENDING ||
			statusBuffer.dwCurrentState == SERVICE_STOP_PENDING)
		{
			Sleep(statusBuffer.dwWaitHint);
			continue;
		}
		if (statusBuffer.dwCurrentState == SERVICE_RUNNING)
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			return statusBuffer.dwProcessId;
		}
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return 0;
}

inline auto CreateProcessAsTrustedInstaller(DWORD pid, string exe_path) -> void
{
	EnablePrivilege(SE_DEBUG_NAME);
	EnablePrivilege(SE_IMPERSONATE_NAME);
	ImpersonateSystem();

	HANDLE hTIProcess;
	if ((hTIProcess = OpenProcess(
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
		FALSE,
		pid)) == nullptr)
	{
		return;
	}

	HANDLE hTIToken;
	if (!OpenProcessToken(
		hTIProcess,
		MAXIMUM_ALLOWED,
		&hTIToken))
	{
		CloseHandle(hTIProcess);
		return;
	}

	HANDLE hDupToken;
	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = nullptr;
	tokenAttributes.bInheritHandle = FALSE;
	if (!DuplicateTokenEx(
		hTIToken,
		MAXIMUM_ALLOWED,
		&tokenAttributes,
		SecurityImpersonation,
		TokenImpersonation,
		&hDupToken))
	{
		CloseHandle(hTIToken);
		return;
	}

	STARTUPINFOW startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
	startupInfo.lpDesktop = LPWSTR(L"Winsta0\\Default");
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
	if (!CreateProcessWithTokenW(
		hDupToken,
		LOGON_WITH_PROFILE,
		LPWSTR(s2ws(exe_path).c_str()),
		nullptr,
		CREATE_UNICODE_ENVIRONMENT,
		nullptr,
		nullptr,
		&startupInfo,
		&processInfo))
	{
		return;
	}
}

inline auto create_process(string exe) -> void
{
	const auto pid = StartTrustedInstallerService();
	CreateProcessAsTrustedInstaller(pid, exe);
}
