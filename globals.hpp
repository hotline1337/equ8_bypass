/**
 *
 * Title: EQU8 User-Mode Bypass and Injector
 * Author: hotline
 *
*/
#pragma once
#include <Windows.h>
#include <functional>
#include <memory>

#include "processuser.hpp"
#include "trustedinstaller.hpp"

using namespace std;

namespace globals
{
	namespace string
	{
		inline auto erase_all_sub_str(std::string& mainStr, const std::string& toErase) -> void
		{
			auto pos = std::string::npos;
			while ((pos = mainStr.find(toErase)) != std::string::npos)
			{
				mainStr.erase(pos, toErase.length());
			}
		}
	}
	namespace validation
	{
		static CHAR path[MAX_PATH];
		inline function<void(void)> validate_system = []()
		{
			bool is_system;
			std::string user;
			GetUserFromProcess(GetCurrentProcessId(), user);

			std::string user_name = getenv("USERPROFILE");
			string::erase_all_sub_str(user_name, "C:\\Users\\");

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
		};
	}
	namespace process
	{
		inline auto get_process_pid_by_name(const char* ProcessName) -> DWORD
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

		inline auto inject_dll(HANDLE handle, std::string_view dll_path) -> void
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
	}
	namespace file
	{
		inline auto open_file_name(const char* filter = "All Files (*.dll)\0*.dll\0", HWND owner = nullptr) -> ::string
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

			::string fileNameStr;
			if (GetOpenFileNameA(&ofn))
				fileNameStr = fileName;
			return fileNameStr;
		}
	}
}
