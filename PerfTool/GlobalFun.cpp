#include "StdAfx.h"
#include "GlobalFun.h"
#include <Psapi.h>
#include <shlobj.h>
#include <math.h>
#include <assert.h>
#pragma comment(lib,"psapi")

#define PROCESS_NAME_NATIVE             0x00000001	// QueryFullProcessImageNameW 使用的第二个参数

BOOL CGlobalFun::AddPrivilege(const CString& strPrivilege)
{
    BOOL bRetVal = FALSE;
    BOOL bResult  = FALSE;
    HANDLE hProcessToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    bResult = ::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hProcessToken);
    if (!bResult)
        goto Exit0;

    bResult = ::LookupPrivilegeValue(NULL, strPrivilege, &luid);
    if (!bResult)
        goto Exit0;

    tp.PrivilegeCount			= 1;
    tp.Privileges[0].Luid		= luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bResult = ::AdjustTokenPrivileges(hProcessToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL);
    if (!bResult)
        goto Exit0;

    bRetVal = TRUE;
Exit0:
    if (hProcessToken)
    {
        ::CloseHandle(hProcessToken);
        hProcessToken = NULL;
    }

    return bRetVal;
}

DWORD CGlobalFun::GetNumberofProcessors()
{
    SYSTEM_INFO si = {0};
    ::GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}

BOOL CGlobalFun::IsWin8System()
{
    BOOL bFunRet = FALSE;
    OSVERSIONINFOEX ovi = {0};
    ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    ::GetVersionEx((OSVERSIONINFO *)&ovi);
    if(ovi.dwMajorVersion == 6 && ovi.dwMinorVersion == 2 && ovi.wProductType == VER_NT_WORKSTATION)
        bFunRet = TRUE;
    return bFunRet;
}

BOOL CGlobalFun::IsVistaSystem()
{
    BOOL bFunRet = FALSE;
    OSVERSIONINFO ovi = {0};
    ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    ::GetVersionEx(&ovi);
    if ((ovi.dwMajorVersion == 6) && (ovi.dwMinorVersion == 0))
        bFunRet = TRUE;
    return bFunRet;
}

BOOL CGlobalFun::IsWin7System()
{
    BOOL bFunRet = FALSE;
    OSVERSIONINFO ovi = {0};

    ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    ::GetVersionEx(&ovi);
    if ((ovi.dwMajorVersion == 6) && (ovi.dwMinorVersion == 1))
        bFunRet = TRUE;
    return bFunRet;
}

BOOL CGlobalFun::IsWin2000System()
{
    BOOL bFunRet = FALSE;
    OSVERSIONINFO ovi = {0};
    ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    ::GetVersionEx(&ovi);
    if ((ovi.dwMajorVersion == 5) && (ovi.dwMinorVersion == 0))
        bFunRet = TRUE;
    return bFunRet;
}

BOOL CGlobalFun::GetProcessFullPath(HANDLE hProcess, LPWSTR lpszFullPath)
{
    BOOL bFunRet = FALSE;
    DWORD dwRet = 0;
    typedef BOOL (WINAPI *pQueryFullProcessImageNameType)(HANDLE, DWORD, LPWSTR, PDWORD);
    static pQueryFullProcessImageNameType pQueryFullProcessImageName = NULL;
    static HMODULE hKernel32 = NULL;
    DWORD dwSize = 0;
    BOOL bTemp = FALSE;

    dwRet = ::GetModuleFileNameEx(hProcess, NULL, lpszFullPath, MAX_PATH);
    if (dwRet != 0)
        goto Exit1;

    if ((!CGlobalFun::IsVistaSystem()) && (!CGlobalFun::IsWin7System()) && !CGlobalFun::IsWin8System())
        goto Exit0;

    hKernel32 = ::LoadLibrary(TEXT("kernel32.dll"));
    if (!hKernel32)
        goto Exit0;

    pQueryFullProcessImageName = (pQueryFullProcessImageNameType)::GetProcAddress(hKernel32, "QueryFullProcessImageNameW");
    if (!pQueryFullProcessImageName)
        goto Exit0;

    dwSize = MAX_PATH;
    bTemp = pQueryFullProcessImageName(hProcess, PROCESS_NAME_NATIVE, lpszFullPath, &dwSize);
    if (!bTemp)
        goto Exit0;

    bTemp = _ConvertDevicePath(lpszFullPath);
    if (!bTemp)
        goto Exit0;

Exit1:
    bFunRet = TRUE;
Exit0:
    if (hKernel32)
    {
        ::FreeLibrary(hKernel32);
        hKernel32 = NULL;
    }
    return bFunRet;	
}

BOOL CGlobalFun::_ConvertDevicePath(LPWSTR lpszFullPath)
{
    DWORD dwRet = 0;
    WCHAR cDevice = TEXT('A');
    WCHAR szDeviceName[3] = { cDevice, TEXT(':'), TEXT('\0') };
    WCHAR szTarget[MAX_PATH] = {0};
    WCHAR szFullPath[MAX_PATH] = {0};
    int nFullPathLen = 0;
    int nTargetLen = 0;

    while (cDevice <= TEXT('Z'))
    {
        szDeviceName[0] = cDevice;
        dwRet = ::QueryDosDevice(szDeviceName, szTarget, MAX_PATH);
        if (dwRet == 0)
        {
            cDevice++;
            continue;
        }

        if (_wcsnicmp(szTarget, lpszFullPath, wcslen(szTarget)) == 0)
        {
            nFullPathLen = (DWORD)wcslen(lpszFullPath);
            nTargetLen = (DWORD)wcslen(szTarget);

            for (int nIndex = 0; nIndex < (nFullPathLen - nTargetLen); nIndex++)
            {
                szFullPath[nIndex] = *(lpszFullPath + nTargetLen + nIndex);
            }

            wcscpy(lpszFullPath, szDeviceName);
            wcscat(lpszFullPath, szFullPath);
            return TRUE;
        }

        cDevice++;
    }

    return TRUE;
}