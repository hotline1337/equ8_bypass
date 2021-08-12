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
#include <functional>

#include "globals.hpp"
#include "xor.hpp"
#include "import.hpp"

using namespace std;

auto main(void) -> int
{
	try
	{
		globals::validation::validate_system();
	}
	catch (std::exception& ex)
	{
		std::string error = "Something went wrong : ";
		error.append(ex.what());
		MessageBoxA(nullptr, error.c_str(), "equ8 bypass", MB_ICONERROR | MB_OK);
		return 0;
	}

	import(SetConsoleTitleA)(xorstr_("equ8 bypass by u55dx"));
	std::cout << xorstr_("~ equ8 bypass by u55dx for unknowncheats\n~ github.com/hotline1337") << std::endl << std::endl;
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
		ioctlHandle = import(CreateFileA).get()(driverDeviceName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
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
	while (globals::process::get_process_pid_by_name("PortalWars-Win64-Shipping.exe") == NULL)
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
	globals::process::inject_dll(h_object, globals::file::open_file_name());
	CloseHandle(h_object);

	std::cout << "~ successfully loaded the buffer\n";
	std::cin.get();
	return 0;
}


