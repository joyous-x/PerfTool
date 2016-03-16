#pragma once
#include <windows.h>
#include <dbghelp.h>
#include <tchar.h>
#include "GlobalFun.h"

class CMiniDump
{
    typedef BOOL (WINAPI *MINIDUMPWRITEDUMP)(	HANDLE hProcess,
        DWORD dwPid,
        HANDLE hFile,
        MINIDUMP_TYPE DumpType,
        CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
        CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
        CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

    struct CSmartModule
    {
        HMODULE m_hModule;

        CSmartModule(HMODULE h)
        {
            m_hModule = h;
        }

        ~CSmartModule()
        {
            if(m_hModule != NULL)
            {
                FreeLibrary(m_hModule);
            }
        }

        operator HMODULE()
        {
            return m_hModule;
        }
    };

    struct CSmartHandle
    {
        HANDLE m_h;

        CSmartHandle(HANDLE h)
        {
            m_h = h;
        }

        ~CSmartHandle()
        {
            if(m_h != NULL && m_h != INVALID_HANDLE_VALUE)
            {
                CloseHandle(m_h);
            }
        }

        operator HANDLE()
        {
            return m_h;
        }
    };

public:
    static BOOL CreateWithMiniDumpType(HMODULE hModule, DWORD dProcessID, const TCHAR* szFile, MINIDUMP_TYPE Dump_Type, LPCRITICAL_SECTION pCS)
    {
        BOOL bRet = FALSE;
        DWORD dwLastError = 0;
        CSmartHandle hImpersonationToken = NULL;
        if(!GetImpersonationToken(&hImpersonationToken.m_h))
        {
            return FALSE;
        }

        CSmartModule hDbgDll = LocalLoadLibrary(hModule, _T("DBGHELP.dll"));
        if(hDbgDll == NULL)
        {
            return FALSE;
        }

        MINIDUMPWRITEDUMP pDumpFunction = (MINIDUMPWRITEDUMP)::GetProcAddress(hDbgDll, "MiniDumpWriteDump");
        if(NULL == pDumpFunction)
        {
            return FALSE;
        }

        CSmartHandle hDumpFile = ::CreateFile(	szFile, 
            GENERIC_READ | GENERIC_WRITE, 
            FILE_SHARE_WRITE | FILE_SHARE_READ, 
            0, CREATE_ALWAYS, 0, 0);
        if(hDumpFile == INVALID_HANDLE_VALUE)
        {
            return FALSE;
        }

        TOKEN_PRIVILEGES tp;
        BOOL bPrivilegeEnabled = EnablePriv(SE_DEBUG_NAME, hImpersonationToken, &tp);

        //> DBGHELP.DLL is not thread safe
        EnterCriticalSection(pCS);

        HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dProcessID);

        if (!hProcess)
        {	//> Vista、Win7下，有些进程是保护的，只能用 PROCESS_QUERY_LIMITED_INFORMATION 来打开
            if (CGlobalFun::IsVistaSystem() ||  CGlobalFun::IsWin7System())
                hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dProcessID);
        }
        if(hProcess)
        {
            bRet = pDumpFunction(hProcess, dProcessID, hDumpFile, Dump_Type, NULL, NULL, NULL);
            ::CloseHandle(hProcess);
        }
        LeaveCriticalSection(pCS);

        if(bPrivilegeEnabled)
        {
            RestorePriv(hImpersonationToken, &tp);
        }
        return bRet;
    }

private:
    // 1.
    static BOOL GetImpersonationToken(HANDLE* phToken)
    {
        *phToken = NULL;
        // 系统函数, 获取当前线程句柄
        if(!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, phToken))
        {
            if(GetLastError() == ERROR_NO_TOKEN)
            {
                // No impersonation token for the curren thread available - go for the process token
                if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, phToken))
                {
                    return FALSE;
                }
            }
            else
            {
                return FALSE;
            }
        }

        return TRUE;
    }

    static BOOL EnablePriv(LPCTSTR pszPriv, HANDLE hToken, TOKEN_PRIVILEGES* ptpOld)
    {
        BOOL bOk = FALSE;

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        bOk = LookupPrivilegeValue( 0, pszPriv, &tp.Privileges[0].Luid);
        if(bOk)
        {
            DWORD cbOld = sizeof(*ptpOld);
            bOk = AdjustTokenPrivileges(hToken, FALSE, &tp, cbOld, ptpOld, &cbOld);
        }

        return (bOk && (ERROR_NOT_ALL_ASSIGNED != GetLastError()));
    }

    static BOOL RestorePriv(HANDLE hToken, TOKEN_PRIVILEGES* ptpOld)
    {
        BOOL bOk = AdjustTokenPrivileges(hToken, FALSE, ptpOld, 0, 0, 0);	
        return (bOk && (ERROR_NOT_ALL_ASSIGNED != GetLastError()));
    }

    static HMODULE LocalLoadLibrary(HMODULE hModule, LPCTSTR pszModule)
    {
        HMODULE hDll = NULL;

        TCHAR pszModulePath[MAX_PATH];
        if(GetModuleFileName(hModule, pszModulePath, sizeof(pszModulePath) / sizeof(pszModulePath[0])))
        {
            TCHAR* pSlash = _tcsrchr(pszModulePath, _T('\\'));
            if(0 != pSlash)
            {
                _tcscpy(pSlash + 1, pszModule);
                hDll = ::LoadLibrary(pszModulePath);
            }
        }

        if(NULL == hDll)
        {
            hDll = ::LoadLibrary(pszModule);
        }

        return hDll;
    }
};