#pragma once

enum EM_PROCESS_END
{
    emModuleOver,
    emTimeOver,
    emProcessOver,
};

struct ST_TRACE_PROCESS_INFO
{
    ST_TRACE_PROCESS_INFO()
    {
        dwModuleCount = 0;
        dwTraceTime = 0;
    }

    DWORD dwModuleCount;
    DWORD dwTraceTime;
    std::wstring wstrProcessName;
};

class ETWProcInfoManager
{
public:
    ETWProcInfoManager(void)
    {
        m_nProcID = -1;
        m_dwLoadModuleCount = 0;
        m_llStartTime = 0;
    }

    ~ETWProcInfoManager(void)
    {
    }

    void SetProcID(int nProcID)
    {
        m_nProcID = nProcID;
    }

    void SetProcInfo(const ST_TRACE_PROCESS_INFO& stProcInfo)
    {
        m_stProcInfo = stProcInfo;
    }

    void SetStartTime(LONGLONG llStartTime)
    {
        m_llStartTime = llStartTime;
    }

    LONGLONG GetStartTime()
    {
        return m_llStartTime;
    }

    DWORD GetTraceTime()
    {
        return m_stProcInfo.dwTraceTime;
    }

    DWORD AddModuleCount()
    {
        return ++m_dwLoadModuleCount;
    }

    DWORD GetTraceModuleCount()
    {
        return m_stProcInfo.dwModuleCount;
    }

    void PrintProcInfo(LONGLONG llCurrentTime, EM_PROCESS_END emOverType)
    {
        std::wstring wstrHead = L"\n--";
        if (emModuleOver == emOverType)
        {
            wstrHead += L"MODULE_COUNT_LOAD_FILL";
        }
        else if (emTimeOver == emOverType)
        {
            wstrHead += L"LOAD_TIME_OVER";
        }
        else if (emProcessOver == emOverType)
        {
            wstrHead += L"PROCESS_OVER";
        }
        else
        {
            return;
        }

        wprintf(L"%s \n", wstrHead.c_str());
        wprintf(L"\t ProcID       =%d \n", m_nProcID);
        wprintf(L"\t ImageName    =%s \n", m_stProcInfo.wstrProcessName.c_str());
        wprintf(L"\t RunTime      =%I64ums \n", (llCurrentTime - m_llStartTime) / 10000);
        wprintf(L"\t ModuleCount  =%d \n", m_dwLoadModuleCount);
    }

private:
    int m_nProcID;
    DWORD m_dwLoadModuleCount;
    LONGLONG m_llStartTime;
    ST_TRACE_PROCESS_INFO m_stProcInfo;
};
