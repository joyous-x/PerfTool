#pragma once
#include <map>
#include "KProcInfo.h"
#include "KCpuUsage.h"
#include "KPathHelper.h"
#include "MiniDump.h"

class KPerfMonitor
{
public:
    KPerfMonitor() : m_hExit(NULL)
    {    }

    DWORD Init() 
    {
        m_hExit = ::CreateEvent(NULL, FALSE, FALSE, NULL);
        if (NULL == m_hExit) return -1;

        InitializeCriticalSection(&m_CS);
        Monitor();

        return 0;
    }

    DWORD Uninit()
    {
        if (m_hExit) ::SetEvent(m_hExit);
        m_hExit = NULL;
        DeleteCriticalSection(&m_CS);
    }

    DWORD Monitor()
    {
        DWORD dwInterval = g_cfg.dwInterval;
        m_CurInfo.RefreshProcInfo();
        while(WAIT_OBJECT_0 != ::WaitForSingleObject(m_hExit, dwInterval))
        {
            m_LastInfo = m_CurInfo;
            m_CurInfo.RefreshProcInfo();

            //> º∆À„cpu percent
            KCpuUsage usage;
            usage.Calculate(m_CurInfo, m_LastInfo, dwInterval);

            Calc();
        }
        return 0;
    }

    DWORD Calc() 
    {
        PROCESS_INFO_INNER* pCur = NULL;
        BOOL bHit = FALSE;
        BOOL bEnd = FALSE;
        BOOL bStart = FALSE;
        CpuHitStatus status = em_hit_none;

        for (DWORD i = 0; i < g_cfg.dwProcNum; i++)
        {
            pCur = m_CurInfo.GetProcInfo(g_cfg.wcsProcNames[i].c_str());
            if (NULL == pCur) continue;

            status = GetStatus(pCur);
            switch(status)
            {
            case em_hit_none:
                pCur->dwHit = 0;
                break;
            case em_hit_first:
                pCur->dwHit++;
                CreateDump(i, pCur->procInfo.strName.c_str(), pCur->procInfo.dwPid, FALSE);
                break;
            case em_hit_last:
                pCur->dwHit = 0;
                CreateDump(i, pCur->procInfo.strName.c_str(), pCur->procInfo.dwPid, TRUE);
                break;
            case em_hit_during:
                pCur->dwHit++;
                break;
            case em_hit_none_after_during:
                pCur->dwHit = 0;
                if (!m_mapPathRecord[i].empty())
                {
                    ::DeleteFile(m_mapPathRecord[i].c_str());
                    m_mapPathRecord[i].clear();
                }
                break;
            default:
                break;
            }

            wprintf(L"%s: %d%%,%d\t", pCur->procInfo.strName.c_str(), pCur->procInfo.dwCpuShow, status);
        }
        wprintf(L"\n");

        return 0;
    }

private:
    CpuHitStatus GetStatus(const PROCESS_INFO_INNER* inner) 
    {
        DWORD dwHit = 0;
        BOOL bHit = FALSE;
        CpuHitStatus emRet = em_hit_none;

        dwHit = inner->dwHit;
        bHit  = IsCpuUsageHit(inner->procInfo.dwCpuShow);

        if (FALSE == bHit) 
        {
            emRet = (0 == dwHit ? em_hit_none : em_hit_none_after_during);
        }
        else 
        {
            dwHit++;
            if (1 == dwHit)
            {
                emRet = em_hit_first;
            }
            else if (IsTimesHit(dwHit))
            {
                emRet = em_hit_last;
            }
            else
            {
                emRet = em_hit_during;
            }
        }

        return emRet;
    }

    DWORD CreateDump(DWORD dwIndex, const wchar_t* pcwcsName, DWORD dwPid, BOOL bEnd)
    {
        std::wstring strPath = m_PathHelper.GetPath(pcwcsName, bEnd);
        if (strPath.empty()) return -1;

        CMiniDump::CreateWithMiniDumpType(NULL, dwPid, strPath.c_str(), MiniDumpWithThreadInfo, &m_CS);
        m_mapPathRecord[dwIndex] = strPath;
        return 0;
    }


    BOOL IsCpuUsageHit(DWORD dwValue)
    {
        return dwValue >= g_cfg.dwPercentThreshold;
    }

    BOOL IsTimesHit(DWORD dwValue)
    {
        return dwValue >= g_cfg.dwTimesThreshold;
    }

public:
    static unsigned __stdcall Run(void* p)
    {
        ((KPerfMonitor*)p)->Monitor();
        return 0;
    }

private:
    HANDLE m_hExit;
    KProcInfo m_CurInfo;
    KProcInfo m_LastInfo;
    KPathHelper m_PathHelper;
    CRITICAL_SECTION m_CS;
    std::map<DWORD, std::wstring> m_mapPathRecord;
};