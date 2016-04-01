//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include "stdafx.h"
#include <algorithm>
#include <vector>
#include <windows.h>
#include <stdio.h>
#include <atlstr.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <Evntcons.h >
#include <process.h>
#include <Tdh.h>
#include <in6addr.h>
#include <string>
#include "ETWPropertyHelper.hpp"
#include "ETWDefines.h"
#include "ETWProcInfoManager.hpp"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")  // For ntohs function
#pragma comment(lib, "winmm.lib")

void WINAPI _EventRecordCallback(PEVENT_RECORD pEventRecord);
void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);
DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo); 

class ETWFindProcName
{
public:
    ETWFindProcName(LPCTSTR lpProcName) : m_lpProcName(lpProcName)
    {
    }

    bool operator()(const std::vector<ST_TRACE_PROCESS_INFO>::value_type& value)
    {
        return !_wcsicmp(value.wstrProcessName.c_str(), m_lpProcName);
    }

private:
    LPCTSTR m_lpProcName;
};

class ETWConsumer
{
public:
    ETWConsumer() : m_hTrace(0)
    {
        TCHAR szFileName[MAX_PATH] = {0};
        ::GetModuleFileName(NULL, szFileName, MAX_PATH);
        ::PathRemoveFileSpec(szFileName);
        ::PathAppend(szFileName, L"TraceObject.ini");

        DWORD dwCount = ::GetPrivateProfileInt(L"PROCESS_COUNT", L"count", 0, szFileName);
        TCHAR szProcName[MAX_PATH] = {0};
        CString strAppName;
        ST_TRACE_PROCESS_INFO procInfo;
        for (DWORD i = 0; i < dwCount; ++i)
        {
            strAppName.Format(L"PROCESS_%d", i);
            procInfo.dwModuleCount = ::GetPrivateProfileInt(strAppName, L"module_count", 10, szFileName);
            procInfo.dwTraceTime = ::GetPrivateProfileInt(strAppName, L"trace_time", 10, szFileName);

            ::GetPrivateProfileString(strAppName, L"process_name", L"", szProcName, MAX_PATH, szFileName);
            procInfo.wstrProcessName = szProcName;
            m_vecProcInfo.push_back(procInfo);
        }

        m_dwTimeID = ::timeSetEvent(10, 10, ETWConsumer::TIMECALLBACK, (DWORD_PTR)this, TIME_PERIODIC);
        m_hHandle[0] = ::CreateSemaphore(NULL, 0, 1000, NULL);
        m_hHandle[1] = ::CreateEvent(NULL, TRUE, FALSE, NULL);
    }

    ~ETWConsumer()
    {
        ::SetEvent(m_hHandle[1]);
        ::timeKillEvent(m_dwTimeID);
        for (std::map<int, ETWProcInfoManager*>::iterator it = m_mapProcManager.begin(); it != m_mapProcManager.end(); ++it)
        {
            delete it->second;
        }

        m_mapProcManager.clear();

        ::CloseHandle(m_hHandle[1]);
        m_hHandle[1] = NULL;

        ::CloseHandle(m_hHandle[0]);
        m_hHandle[0] = NULL;
    }

    DWORD OpenTrace()
    {
        ULONG nRet = ERROR_SUCCESS;
        EVENT_TRACE_LOGFILE trace;
        TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;

        ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
        trace.LoggerName = SESSION_NAME;
        trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        trace.EventRecordCallback = &_EventRecordCallback;
        trace.Context = this;

        m_hTrace = ::OpenTrace(&trace);
        if ((TRACEHANDLE)INVALID_HANDLE_VALUE == m_hTrace)
        {
            goto cleanup;
        }

        _beginthreadex(NULL, 0, ETWConsumer::Process, this, 0, 0);
cleanup:
        if (nRet != ERROR_SUCCESS)
        {
            this->CloseTrace();
        }

        return nRet;
    }

    static unsigned __stdcall Process(void* arg)
    {
        ((ETWConsumer*)arg)->ProcessTrace();
        return 0;
    }

    DWORD ProcessTrace()
    {
        ULONG nRet = ERROR_SUCCESS;

        do
        {
            nRet = ::ProcessTrace(&m_hTrace, 1, 0, 0);
            if (nRet != ERROR_SUCCESS && nRet != ERROR_CANCELLED)
            {
                break;
            }
        }while(FALSE);

        return nRet;
    }

    DWORD CloseTrace()
    {
        ULONG uRet = ERROR_SUCCESS;
        if ((TRACEHANDLE)INVALID_HANDLE_VALUE != m_hTrace)
        {
            uRet = ::CloseTrace(m_hTrace);
            m_hTrace = (TRACEHANDLE)INVALID_HANDLE_VALUE;
        }
        return uRet;
    }

    DWORD EventRecordCallback(PEVENT_RECORD pEvent)
    {
        if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
            pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
        {
            return 0; // Skip this event.
        }

        DWORD status = ERROR_SUCCESS;
        EventData         stEventData;
        ETWPropertyHelper etwHelper(pEvent);

        if (FALSE == etwHelper.IsTargetEvent(pEvent, &stEventData))
        {
            goto cleanup;
        }

        etwHelper.GetToplevelPropertys(pEvent, &stEventData);
        DistributeData(&stEventData, pEvent);
        //PrintData(&stEventData);
        //etwHelper.GetTimeStamp();
cleanup:
        return status;
    }

private:
    void DistributeData(EventData* pEvent, PEVENT_RECORD pEventRecord)
    {
        int nProcID = -1;
        LPCTSTR lpProcName = NULL;
        if (event_type__process == pEvent->dwEventType)
        {
            nProcID = pEvent->proc.dwProcID;
            lpProcName = ::PathFindFileName(pEvent->proc.wstrImageName.c_str());
        } 
        else if (event_type__image == pEvent->dwEventType)
        {
            nProcID = pEvent->image.dwProcID;
            lpProcName = ::PathFindFileName(pEvent->image.wstrImageName.c_str());
        }
        else
        {
            return;
        }

        ATL::CComCritSecLock<CComAutoCriticalSection> guard(m_cs);
        std::map<int, ETWProcInfoManager*>::iterator itID = m_mapProcManager.find(nProcID);
        std::vector<ST_TRACE_PROCESS_INFO>::iterator itName = std::find_if(m_vecProcInfo.begin(), m_vecProcInfo.end(), ETWFindProcName(lpProcName));
        if (itName != m_vecProcInfo.end())
        {
            if (event_type__process == pEvent->dwEventType)
            {
                if (action_type__start == pEvent->dwActionType) //进程启动
                {
                    ETWProcInfoManager* pProcManager = new ETWProcInfoManager();
                    pProcManager->SetProcInfo(*itName);
                    pProcManager->SetProcID(nProcID);
                    pProcManager->SetStartTime(pEventRecord->EventHeader.TimeStamp.QuadPart);
                    m_mapProcManager[nProcID] = pProcManager;
                    ::ReleaseSemaphore(m_hHandle[0], 1, NULL);
                }
                else if ((action_type__end == pEvent->dwActionType) && (itID != m_mapProcManager.end())) //进程结束
                {
                    PrintProcInfo(itID, pEventRecord->EventHeader.TimeStamp.QuadPart, emProcessOver);
                }
            }
        }
        else if (itID != m_mapProcManager.end())
        {
            if (itID->second->AddModuleCount() >= itID->second->GetTraceModuleCount()) //模块加载达到上限
            {
                PrintProcInfo(itID, pEventRecord->EventHeader.TimeStamp.QuadPart, emModuleOver);
            }
            else if ((pEventRecord->EventHeader.TimeStamp.QuadPart - itID->second->GetStartTime()) >= (itID->second->GetTraceTime() * 10000000)) //超时
            {
                PrintProcInfo(itID, pEventRecord->EventHeader.TimeStamp.QuadPart, emTimeOver);
            }
        }
    }

    void PrintProcInfo(std::map<int, ETWProcInfoManager*>::iterator it, LONGLONG llTime, EM_PROCESS_END emOverType)
    {
        ::WaitForSingleObject(m_hHandle[0], 1);
        it->second->PrintProcInfo(llTime, emOverType);
        delete it->second;
        m_mapProcManager.erase(it);
    }

    static void CALLBACK TIMECALLBACK(UINT uTimerID, UINT uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2)
    {
        ETWConsumer* pConsumer = (ETWConsumer*)dwUser;
        if (!pConsumer)
        {
            return;
        }

        ::WaitForMultipleObjects(2, pConsumer->m_hHandle, FALSE, INFINITE);
        ::ReleaseSemaphore(pConsumer->m_hHandle[0], 1, NULL);

        SYSTEMTIME st;
        ::GetSystemTime(&st);

        FILETIME ft;
        ::SystemTimeToFileTime(&st, &ft);

        LARGE_INTEGER llCurrentTime;
        llCurrentTime.HighPart = ft.dwHighDateTime;
        llCurrentTime.LowPart = ft.dwLowDateTime;

        ATL::CComCritSecLock<CComAutoCriticalSection> guard(pConsumer->m_cs);
        for (std::map<int, ETWProcInfoManager*>::iterator it = pConsumer->m_mapProcManager.begin(); it != pConsumer->m_mapProcManager.end();)
        {
            if ((llCurrentTime.QuadPart - it->second->GetStartTime()) > (it->second->GetTraceTime() * 10000000)) //超时
            {
                pConsumer->PrintProcInfo(it++, llCurrentTime.QuadPart, emTimeOver);
            }
            else
            {
                ++it;
            }
        }
    }

    void PrintData(EventData* pEvent) 
    {
        std::wstring wstrHead = L"\n--";

        if (pEvent->dwEventType == event_type__process)
        {
            wstrHead += L"EVENT_PROCESS";
        }
        else if (pEvent->dwEventType == event_type__image)
        {
            wstrHead += L"EVENT_IMAGE_LOAD";
        }
        else 
        {
            return ;
        }

        wstrHead += L" Action:";
        if (pEvent->dwActionType == action_type__start)
        {
            if (pEvent->dwEventType == event_type__image)
            {
                wstrHead += L"Load";
            }
            else
            {
                wstrHead += L"Start";
            }
        }
        else if (pEvent->dwActionType == action_type__end)
        {
            if (pEvent->dwEventType == event_type__image)
            {
                wstrHead += L"Unload";
            }
            else
            {
                wstrHead += L"Stop";
            }
        }
        else
        {
            wstrHead += L"Unknown";
        }

        wprintf(L"%s \n", wstrHead.c_str());
        if (pEvent->dwEventType == event_type__process)
        {
            wprintf(L"\t ProcID       =%d \n", pEvent->proc.dwProcID);
            wprintf(L"\t ApplicationID=%d \n", pEvent->proc.dwApplicationID);
            wprintf(L"\t ImageName    =%s \n", pEvent->proc.wstrImageName.c_str());
            wprintf(L"\t CommandLine  =%s \n", pEvent->proc.wstrCommandLine.c_str());
        }
        else if (pEvent->dwEventType == event_type__image)
        {
            wprintf(L"\t ProcID   =%d \n", pEvent->image.dwProcID);
            wprintf(L"\t ImageSize=%d \n", pEvent->image.dwImageSize);
            wprintf(L"\t ImageName=%s \n", pEvent->image.wstrImageName.c_str());
        }
    }

private:
    TRACEHANDLE m_hTrace;
    DWORD m_dwTimeID;
    HANDLE m_hHandle[2];
    ATL::CComAutoCriticalSection m_cs;
    std::vector<ST_TRACE_PROCESS_INFO> m_vecProcInfo;
    std::map<int, ETWProcInfoManager*> m_mapProcManager;
};

void WINAPI _EventRecordCallback(PEVENT_RECORD pEventRecord)
{
    ((ETWConsumer*)(pEventRecord->UserContext))->EventRecordCallback(pEventRecord);
}