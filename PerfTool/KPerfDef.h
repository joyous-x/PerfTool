#pragma once
#include <string>
#include <vector>

typedef struct ST_PROCESS_INFO 
{
    DWORD   dwSize;
    DWORD   dwPid;          // 进程的 PID
    DWORD   dwParentPid;    // 父进程 PID

    UINT64   ulCreateTime;   // 进程创建时间
    UINT64   ulLife;         // 进程生命周期 *
    UINT64   ulCpuUser;      // 用户态cpu时间
    UINT64   ulCpuKernel;    // 内核态cpu时间

    DWORD   dwCpuShow;          // 任务管理器看到的CPU占用 （d%）
    DWORD   dwCpuShowPeak;      // 任务管理器看到的CPU占用 （d%）
    DWORD   dwCpuPercentUser;   // 当前用户占用 CPU （d%）
    DWORD   dwCpuPercentKernel; // 当前内核占用 CPU （d%）
    DWORD   dwCpuPeakUser;      // CPU 用户使用峰值（d%）
    DWORD   dwCpuPeakKernel;    // CPU 内核使用峰值（d%）

    DWORD   dwWorkingSetCur;    // 当前内存使用值（单位：KB）
    DWORD   dwWorkingSetInc;    // 内存使用增量（单位：KB）
    DWORD   dwWorkingSetPeak;   // 内存使用峰值（单位：KB）

    std::wstring strName;       // 进程名，如：explorer.exe

    ST_PROCESS_INFO() : dwPid(0), dwParentPid(0), ulCreateTime(0), ulLife(0), ulCpuUser(0),  ulCpuKernel(0)
        , dwCpuPercentUser(0), dwCpuPercentKernel(0), dwCpuPeakUser(0), dwCpuPeakKernel(0)
        , dwWorkingSetCur(0), dwWorkingSetInc(0), dwWorkingSetPeak(0), dwCpuShow(0), dwCpuShowPeak(0)
    {
        dwSize = sizeof(ST_PROCESS_INFO);
    }
}PROCESS_INFO;


typedef struct ST_PROCESS_INFO_INNER 
{
    PROCESS_INFO procInfo;
    DWORD        dwHit;

    ST_PROCESS_INFO_INNER() : dwHit(0)
    {    }
}PROCESS_INFO_INNER;

enum CpuHitStatus
{
    em_hit_none = 1,
    em_hit_none_after_during,
    em_hit_first,
    em_hit_last,
    em_hit_during,
};

#define DefaultPercentThreshold    (4)
#define DefaultTimesThreshold      (4)
#define DefaultInterval            (1000)

#define DefaultProcNum             (2)
#define DefaultProcName1           L"qq.exe"
#define DefaultProcName2           L"notepad++.exe"
#define DefaultProcNames           (L"qq.exe;notepad++.exe;")

typedef struct ST_GLOBAL_CFG
{
    DWORD dwPercentThreshold;
    DWORD dwTimesThreshold;
    DWORD dwInterval;
    DWORD dwProcNum;
    std::vector<std::wstring> wcsProcNames;
    ST_GLOBAL_CFG() : dwPercentThreshold(0), dwTimesThreshold(0), dwInterval(0), dwProcNum(0)
    {
        wcsProcNames.clear();
        default();
    }

    void default()
    {
        dwPercentThreshold = DefaultPercentThreshold;
        dwTimesThreshold = DefaultTimesThreshold;
        dwInterval = DefaultInterval;
        dwProcNum = DefaultProcNum;
        wcsProcNames.clear();
        wcsProcNames.push_back(DefaultProcName1);
        wcsProcNames.push_back(DefaultProcName2);
    }
}GLOBAL_CFG;

extern GLOBAL_CFG g_cfg;


