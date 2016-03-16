#pragma once

#include "KPerfDef.h"
#include "KProcInfo.h"
#include "KProcInfo.h"

class KCpuUsage
{
public:
    friend class KPerfInfo;

    KCpuUsage()
    {
        m_dwProcessorNum = CGlobalFun::GetNumberofProcessors();
    }

    DWORD Calculate(KProcInfo& cur, KProcInfo& last, DWORD dwInterval)
    {
        for (DWORD i = 0; i < g_cfg.dwProcNum; i++)
        {
            PROCESS_INFO_INNER* pCur = NULL;
            PROCESS_INFO_INNER* pLast = NULL;
            pCur = cur.GetProcInfo(g_cfg.wcsProcNames[i].c_str());
            if (NULL == pCur) continue;

            pLast = last.GetProcInfo(g_cfg.wcsProcNames[i].c_str());
            if (NULL == pCur) continue;

            GetCPUUsage(&pCur->procInfo, &pLast->procInfo, dwInterval);
        }
        return 0;
    }

private:
    DWORD GetCPUUsage(PROCESS_INFO* pPInfoNow, PROCESS_INFO* pPInfoLast, DWORD dwInterval)
    {
        pPInfoNow->dwCpuPercentKernel = CalculateUsagePercent(pPInfoNow->ulCpuKernel, pPInfoLast->ulCpuKernel, dwInterval);
        pPInfoNow->dwCpuPercentUser   = CalculateUsagePercent(pPInfoNow->ulCpuUser, pPInfoLast->ulCpuUser, dwInterval);
        pPInfoNow->dwCpuShow = CalculateShowPercent(
                                    pPInfoNow->ulCpuKernel, pPInfoLast->ulCpuKernel, 
                                    pPInfoNow->ulCpuUser, pPInfoLast->ulCpuUser, dwInterval);

        pPInfoNow->dwCpuShowPeak = pPInfoNow->dwCpuShow;
        pPInfoNow->dwCpuPeakUser = pPInfoNow->dwCpuPercentUser;
        pPInfoNow->dwCpuPeakKernel = pPInfoNow->dwCpuPercentKernel;

        if (pPInfoLast->dwCpuPeakUser > pPInfoNow->dwCpuPeakUser)
        {
            pPInfoNow->dwCpuPeakUser =  pPInfoLast->dwCpuPeakUser;
        }

        if (pPInfoLast->dwCpuPeakKernel > pPInfoNow->dwCpuPeakKernel)
        {
            pPInfoNow->dwCpuPeakKernel =  pPInfoLast->dwCpuPeakKernel;
        }

        if (pPInfoLast->dwCpuShowPeak > pPInfoNow->dwCpuShowPeak)
        {
            pPInfoNow->dwCpuShowPeak =  pPInfoLast->dwCpuShowPeak;
        }

        return 0;
    }

    DWORD CalculateUsagePercent(ULONGLONG ulCur, ULONGLONG ulLast, DWORD dwIntervel) 
    {
        DWORD dwFunRet = 0;
        ULONGLONG uWorkingTimeMs = 0;

        uWorkingTimeMs = (ulCur - ulLast) / 10000; //> 100纳秒 转 毫秒
        dwIntervel = (dwIntervel == 0 ? 1 : dwIntervel);
        dwFunRet = (DWORD)((uWorkingTimeMs * 100) / (dwIntervel * m_dwProcessorNum));

        return min(dwFunRet, 100);
    }

    DWORD CalculateShowPercent(ULONGLONG ulCurKernel, ULONGLONG ulLastKernel, ULONGLONG ulCurUser, ULONGLONG ulLastUser, DWORD dwIntervel)
    {
        DWORD dwFunRet = 0;
        ULONGLONG uWorkingTimeMs = 0;

        uWorkingTimeMs = (ulCurKernel - ulLastKernel) + (ulCurUser - ulLastUser);
        uWorkingTimeMs /= 10000; //> 100纳秒 转 毫秒
        uWorkingTimeMs /= m_dwProcessorNum;

        dwIntervel = (dwIntervel == 0 ? 1 : dwIntervel);
        dwFunRet   = ((uWorkingTimeMs * 100) + (dwIntervel >> 1)) / dwIntervel; //> 加上 dwIntervel >> 1 是为了：四舍五入

        return min(dwFunRet, 100);
    }
private:
    DWORD   m_dwProcessorNum;
    DWORD   m_dwHit;
};