//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
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

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")  // For ntohs function

void WINAPI _EventRecordCallback(PEVENT_RECORD pEventRecord);
void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);
DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo); 

class ETWConsumer
{
public:
    ETWConsumer() : m_hTrace(0)
    { }

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
        PrintData(&stEventData);
        etwHelper.GetTimeStamp();
cleanup:
        return status;
    }

private:
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
};

void WINAPI _EventRecordCallback(PEVENT_RECORD pEventRecord)
{
    ((ETWConsumer*)(pEventRecord->UserContext))->EventRecordCallback(pEventRecord);
}
