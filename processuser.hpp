/**
 *
 * Title: EQU8 User-Mode Bypass and Injector
 * Author: hotline
 *
*/
#pragma once
#include <Windows.h>
#include <string>

#define MAX_NAME 256

inline auto GetLogonFromToken(HANDLE hToken, std::string& strUser) -> BOOL
{
    DWORD dwSize = MAX_NAME;
    BOOL bSuccess = FALSE;
    DWORD dwLength = 0;
    strUser = "";
    PTOKEN_USER ptu = nullptr;
    //Verify the parameter passed in is not NULL.
    if (nullptr == hToken)
        goto Cleanup;

    if (!GetTokenInformation(
        hToken,         // handle to the access token
        TokenUser,    // get information about the token's groups 
        static_cast<LPVOID>(ptu),   // pointer to PTOKEN_USER buffer
        0,              // size of buffer
        &dwLength       // receives required buffer size
        ))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            goto Cleanup;

        ptu = static_cast<PTOKEN_USER>(HeapAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY, dwLength));

        if (ptu == nullptr)
            goto Cleanup;
    }

    if (!GetTokenInformation(
        hToken,         // handle to the access token
        TokenUser,    // get information about the token's groups 
        static_cast<LPVOID>(ptu),   // pointer to PTOKEN_USER buffer
        dwLength,       // size of buffer
        &dwLength       // receives required buffer size
        ))
    {
        goto Cleanup;
    }
    SID_NAME_USE SidType;
    char lpName[MAX_NAME];
    char lpDomain[MAX_NAME];

    if (!LookupAccountSidA(nullptr, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
    {
        const DWORD dwResult = GetLastError();
        if (dwResult == ERROR_NONE_MAPPED)
            strcpy_s(lpName, "NONE_MAPPED");
    }
    else
    {
        strUser = lpName;
        bSuccess = TRUE;
    }

Cleanup:

    if (ptu != nullptr)
        HeapFree(GetProcessHeap(), 0, static_cast<LPVOID>(ptu));
    return bSuccess;
}

inline auto GetUserFromProcess(const DWORD procId, std::string& strUser) -> HRESULT
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
    if (hProcess == nullptr)
        return E_FAIL;
    HANDLE hToken = nullptr;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProcess);
        return E_FAIL;
    }
    BOOL bres = GetLogonFromToken(hToken, strUser);

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return bres ? S_OK : E_FAIL;
}