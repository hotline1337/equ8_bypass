/**
 *
 * Title: EQU8 User-Mode Bypass and Injector
 * Author: hotline
 *
*/
#include <Windows.h>
#include <cstdio>
#include <string>
#include <TlHelp32.h>
#include <iostream>

#include "processuser.hpp"
#include "trustedinstaller.hpp"

static CHAR path[MAX_PATH];

void erase_all_sub_str(std::string& mainStr, const std::string& toErase)
{
	auto pos = std::string::npos;
	while ((pos = mainStr.find(toErase)) != std::string::npos)
	{
		mainStr.erase(pos, toErase.length());
	}
}

void validate_system()
{
	bool is_system;
	std::string user;
	GetUserFromProcess(GetCurrentProcessId(), user);

	std::string user_name = getenv("USERPROFILE");
	erase_all_sub_str(user_name, "C:\\Users\\");

	if (user == user_name)
	{
		is_system = false;
	}
	else
	{
		is_system = true;
	}

	GetModuleFileNameA(nullptr, path, MAX_PATH);
	if (!is_system)
	{
		create_process(path);
		TerminateProcess(GetCurrentProcess(), 0);
	}
}

DWORD get_process_pid_by_name(const char* ProcessName)
{
	PROCESSENTRY32 entry;

	entry.dwSize = sizeof(PROCESSENTRY32);
	DWORD targetProcessId = 0;
	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, ProcessName) == 0)
			{
				targetProcessId = entry.th32ProcessID;
				break;
			}
		}
	}
	CloseHandle(snapshot);
	return targetProcessId;
}

void inject_dll(HANDLE handle, std::string_view dll_path)
{
	auto* dll_path_addr = VirtualAllocEx(handle, nullptr, dll_path.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!dll_path_addr)
		return;

	if (!WriteProcessMemory(handle, dll_path_addr, dll_path.data(), dll_path.size(), nullptr))
		return;

	const auto remote_thread = CreateRemoteThread(handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA),
	                                              dll_path_addr, 0, nullptr);
	if (!remote_thread)
		return;

	WaitForSingleObject(remote_thread, INFINITE);
}

std::string open_file_name(const char* filter = "All Files (*.dll)\0*.dll\0", HWND owner = nullptr)
{
	OPENFILENAME ofn;
	char fileName[MAX_PATH] = "";
	memset(&ofn, 0, sizeof(ofn));

	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = owner;
	ofn.lpstrFilter = filter;
	ofn.lpstrFile = fileName;
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
	ofn.lpstrDefExt = "";

	string fileNameStr;
	if (GetOpenFileNameA(&ofn))
		fileNameStr = fileName;
	return fileNameStr;
}

int main(void)
{
	try
	{
		validate_system();
	}
	catch (std::exception& ex)
	{
		std::string error = "Something went wrong : ";
		error.append(ex.what());
		MessageBoxA(nullptr, error.c_str(), "equ8 bypass", MB_ICONERROR | MB_OK);
		return 0;
	}

	LI_FN(SetConsoleTitleA)(xorstr_("equ8 bypass by u55dx"));
	std::cout << xorstr_("~ equ8 bypass by u55dx for unknowncheats") << std::endl << std::endl;
	std::cout << "~ successfully launched as system" << std::endl;

	/* variables */
	int lastError;
	int lastErrorHistory = 0;
	HANDLE ioctlHandle;
	HKEY equ8DriverKey;
	CHAR deviceSessionId[MAX_PATH];
	DWORD deviceSessionIdLength = sizeof(deviceSessionId);

	LSTATUS status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"(SYSTEM\CurrentControlSet\Services\EQU8_HELPER_36)", 0,
	                               KEY_READ, &equ8DriverKey);
	if (status != ERROR_SUCCESS)
	{
		std::cout << "~ failed to open equ8 driver key : " << std::hex << status << "\n";
		std::cin.get();
		return 0;
	}

	status = RegQueryValueExA(equ8DriverKey, "SessionId", nullptr, nullptr, reinterpret_cast<LPBYTE>(deviceSessionId),
	                          &deviceSessionIdLength);
	if (status != ERROR_SUCCESS)
	{
		std::cout << "~ failed to query equ8 session id : " << std::hex << status << "\n";
		std::cin.get();
		return 0;
	}

	const std::string driverDeviceName = "\\??\\" + std::string(deviceSessionId);
	std::cout << "~ found equ8 driver : " << driverDeviceName << "\n";
	std::cout << "~ waiting for game\n";

	do
	{
		ioctlHandle = CreateFileA(driverDeviceName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
		                          FILE_ATTRIBUTE_NORMAL, nullptr);
		lastError = GetLastError();
		if (lastErrorHistory != lastError)
		{
			if (lastErrorHistory == 0 && lastError == ERROR_NO_SUCH_DEVICE)
			{
				std::cout << "~ failed to get device handle\n";
			}
			if (lastErrorHistory == ERROR_NO_SUCH_DEVICE && lastError != ERROR_SUCCESS)
			{
				std::cout << "~ failed to find the device\n";
			}
			lastErrorHistory = lastError;
		}
	}
	while (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_ACCESS_DENIED || lastError == ERROR_NO_SUCH_DEVICE);

	if (ioctlHandle == INVALID_HANDLE_VALUE)
	{
		std::cout << "~ failed to get device handle due to unhandled error : " << std::hex << lastError << "\n";
		std::cin.get();
		return 0;
	}

	std::cout << "~ successfully opened equ8 driver : " << std::hex << reinterpret_cast<ULONG64>(ioctlHandle) << "\n";
	while (get_process_pid_by_name("PortalWars-Win64-Shipping.exe") == NULL)
	{
		Sleep(50);
	}

	std::cout << "~ received handle to the game\n";
	CloseHandle(ioctlHandle);

	std::cout << "~ equ8 unloaded successfully\n";
	std::cout << "~ waiting for window\n";
	while (!FindWindowA(nullptr, "PortalWars  "))
	{
		Sleep(100);
	}

	DWORD split_gate_pid = 0;
	GetWindowThreadProcessId(FindWindowA(nullptr, "PortalWars  "), &split_gate_pid);

	const HANDLE h_object = OpenProcess(PROCESS_ALL_ACCESS, false, split_gate_pid);
	if (!h_object)
	{
		std::cout << "~ failed to get handle to process\n";
		std::cin.get();
		return 0;
	}
	std::cout << "~ opening file dialog\n";
	inject_dll(h_object, open_file_name());
	CloseHandle(h_object);

	std::cout << "~ successfully loaded the buffer\n";
	std::cin.get();
	return 0;
}

