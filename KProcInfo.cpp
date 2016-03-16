#include "stdafx.h"
#include "KProcInfo.h"
#include "GlobalFun.h"

UINT64 FileTimeToInt64(const FILETIME& time)  
{  
    ULARGE_INTEGER tt;
    tt.LowPart = time.dwLowDateTime;
    tt.HighPart = time.dwHighDateTime;
    return(tt.QuadPart);
}

DWORD KProcInfo::RefreshProcInfo()
{
    std::vector<PROCESSENTRY32> vecProc;

    DWORD dwRet = -1;
    dwRet = GetProcessList32(vecProc);
    if (0 != dwRet) goto Exit0;

    for (DWORD i = 0; i < g_cfg.dwProcNum; i++)
    {
        DWORD dwTmp = 0;
        PROCESS_INFO_INNER inner;

        dwTmp = QueryProcessID(g_cfg.wcsProcNames[i].c_str(), vecProc, &inner.procInfo);
        if (0 != dwTmp) continue;

        dwTmp = GetProcessTimes(inner.procInfo.dwPid, &inner.procInfo);
        if (0 != dwTmp) continue;

        inner.procInfo.strName = g_cfg.wcsProcNames[i];
        m_mapProcInfo[inner.procInfo.strName].procInfo = inner.procInfo;
    }

    dwRet = 0;
Exit0:
    return dwRet;
}

DWORD KProcInfo::GetProcessTimes(DWORD dwPid, PROCESS_INFO* pProcInfo) 
{
    DWORD dwRet = -1;
    BOOL  bRet  = FALSE;
    FILETIME ftCreateionTime = {0};
    FILETIME ftExitTime = {0};
    FILETIME ftKernelTime = {0};
    FILETIME ftUserTime = {0};
    HANDLE  hProcess = GetProcessHandle(dwPid);
    if (NULL == hProcess) goto Exit0;

    bRet = ::GetProcessTimes(hProcess, &ftCreateionTime, &ftExitTime, &ftKernelTime, &ftUserTime);
    if (FALSE == bRet) goto Exit0;

    pProcInfo->ulCreateTime = FileTimeToInt64(ftCreateionTime);
    pProcInfo->ulCpuKernel  = FileTimeToInt64(ftKernelTime);
    pProcInfo->ulCpuUser    = FileTimeToInt64(ftUserTime);
    dwRet = 0;
Exit0:
    if (NULL != hProcess) ::CloseHandle(hProcess);
    return dwRet;
}

DWORD KProcInfo::GetProcessList32(std::vector<PROCESSENTRY32>& vecProc)
{
    DWORD dwRet = -1;
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;

    hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        goto Exit0;

    if (!::Process32First(hSnapshot, &pe))
        goto Exit0;

    do
    {
        vecProc.push_back(pe);
    }while (::Process32Next(hSnapshot, &pe));

    dwRet = 0;
Exit0:
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(hSnapshot);
        hSnapshot = INVALID_HANDLE_VALUE;
    }

    return dwRet;
}

DWORD KProcInfo::QueryProcessID(const wchar_t* pcwcsName, std::vector<PROCESSENTRY32>& vecProc, PROCESS_INFO* pInfo)
{
    if (NULL == pcwcsName || 0 == vecProc.size()) return 0;

    DWORD dwPid = -1;
    for (DWORD i = 0; i < vecProc.size(); i++)
    {
        if (0 == _wcsicmp(pcwcsName, vecProc[i].szExeFile)) 
        {
            pInfo->dwPid = vecProc[i].th32ProcessID;
            pInfo->dwParentPid = vecProc[i].th32ParentProcessID;
            dwPid = 0;
            break;
        }
    }

    return dwPid;
}

HANDLE KProcInfo::GetProcessHandle(DWORD dwPid) 
{
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
    if (!hProcess)
    {	// Vista、Win7下，有些进程是保护的，只能用 PROCESS_QUERY_LIMITED_INFORMATION 来打开
        if (CGlobalFun::IsWin8System() || CGlobalFun::IsWin7System() || CGlobalFun::IsVistaSystem())
        {
            hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
        }
    }

    return hProcess;
}