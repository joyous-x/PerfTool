#pragma once

#include <TlHelp32.h>
#include <map>
#include <vector>
#include <string>
#include "KPerfDef.h"

class KProcInfo
{
public:
    DWORD RefreshProcInfo();
    BOOL IsHit(const wchar_t* pcwcsName);
    PROCESS_INFO_INNER* GetProcInfo(const wchar_t* pcwcsName)
    {
        std::map<std::wstring, PROCESS_INFO_INNER>::iterator iter;
        iter = m_mapProcInfo.find(pcwcsName);
        if (iter == m_mapProcInfo.end())
        {
            return NULL;
        }

        return &iter->second;
    }

private:
    DWORD GetProcessTimes(DWORD dwPid, PROCESS_INFO* pProcInfo);

    DWORD GetProcessList32(std::vector<PROCESSENTRY32>& vecProc);

    DWORD QueryProcessID(const wchar_t* pcwcsName, std::vector<PROCESSENTRY32>& vecProc, PROCESS_INFO* pInfo);

    HANDLE GetProcessHandle(DWORD dwPid);
public:
    std::map<std::wstring, PROCESS_INFO_INNER> m_mapProcInfo;
};