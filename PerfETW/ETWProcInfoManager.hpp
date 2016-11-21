#pragma once

enum EM_PROCESS_END
{
    emModuleOver,
    emTimeOver,
    emProcessOver,
    emProcWindowsShow,
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
        m_bWindowShow = FALSE;
        m_dwLoadModuleCount = 0;
        m_llStartTime = 0;
        m_llStartTimeTwo = 0;
    }

    ~ETWProcInfoManager(void)
    {
    }

    void SetProcID(int nProcID)
    {
        m_nProcID = nProcID;
    }

    DWORD GetProcID()
    {
        return m_nProcID;
    }

    void SetProcInfo(const ST_TRACE_PROCESS_INFO& stProcInfo)
    {
        m_stProcInfo = stProcInfo;
    }

    void SetStartTime(LONGLONG llStartTime)
    {
        m_llStartTime = llStartTime;
    }

    void SetStartTimeTwo(LONGLONG llStartTimeTwo)
    {
        m_llStartTimeTwo = llStartTimeTwo;
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

    void SetWindowShow(BOOL bWindowShow)
    {
        m_bWindowShow = bWindowShow;
    }

    BOOL IsWindowShow()
    {
        return m_bWindowShow;
    }

    void PrintProcInfo(LONGLONG llCurrentTime, EM_PROCESS_END emOverType)
    {
        LONGLONG llCostTime = llCurrentTime - m_llStartTime;
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
        else if (emProcWindowsShow == emOverType)
        {
            wstrHead += L"WINDOW SHOW";
            llCostTime = llCurrentTime - m_llStartTimeTwo;
        }
        else
        {
            return;
        }

        wprintf(L"%s \n", wstrHead.c_str());
        wprintf(L"\t ProcID       =%d \n", m_nProcID);
        wprintf(L"\t ImageName    =%s \n", m_stProcInfo.wstrProcessName.c_str());
        wprintf(L"\t RunTime      =%I64ums \n", llCostTime / 10000);
        wprintf(L"\t ModuleCount  =%d \n", m_dwLoadModuleCount);
    }

private:
    int m_nProcID;
    BOOL m_bWindowShow;
    DWORD m_dwLoadModuleCount;
    LONGLONG m_llStartTime;
    LONGLONG m_llStartTimeTwo;
    ST_TRACE_PROCESS_INFO m_stProcInfo;
};
