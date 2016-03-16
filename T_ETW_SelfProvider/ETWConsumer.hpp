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
#include <tdh.h>
#include "ETWDefines.h"

#pragma comment(lib, "tdh.lib")

#define LOGFILE_PATH L"D:\\Log.etl"
void WINAPI _EventCallback(PEVENT_TRACE pEvent);
void WINAPI _EventRecordCallback(PEVENT_RECORD pEventRecord);

class ETWConsumer
{
public:
    ETWConsumer() : m_TimerResolution(0), m_bUserMode(FALSE), m_hTrace(0)
    { }

    DWORD OpenTrace()
    {
        ULONG nRet = ERROR_SUCCESS;
        EVENT_TRACE_LOGFILE trace;
        TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;

        ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
        trace.LoggerName = SESSION_NAME;
//         // Specify this callback if consuming events from a provider that used one of the EventWrite functions to log events.
//         trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
//         trace.EventRecordCallback = &_EventRecordCallback;
        trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME;
        trace.EventCallback = (PEVENT_CALLBACK) (_EventCallback);
        trace.Context = this;

        m_hTrace = ::OpenTrace(&trace);
        if ((TRACEHANDLE)INVALID_HANDLE_VALUE == m_hTrace)
        {
            goto cleanup;
        }

        //> 目前取值不准
        m_bUserMode = pHeader->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;

        if (pHeader->TimerResolution > 0)
        {
            m_TimerResolution = pHeader->TimerResolution / 10000;
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
        DWORD BufferSize = 0;
        PTRACE_EVENT_INFO pInfo = NULL;
        DWORD PointerSize = 0;

        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
        if (ERROR_INSUFFICIENT_BUFFER == status)
        {
            pInfo = (TRACE_EVENT_INFO*) malloc(BufferSize);
            if (pInfo == NULL)
            {
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }

            status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
        }

        if (ERROR_SUCCESS != status)
        {
            goto cleanup;
        }
cleanup:
        if (pInfo)
        {
            free(pInfo);
        }
        return status;
    }

private:
    // Used to calculate CPU usage
    ULONG m_TimerResolution;

    // Used to determine if the session is a private session or kernel session.
    // You need to know this when accessing some members of the EVENT_TRACE.Header
    // member (for example, KernelTime or UserTime).
    BOOL m_bUserMode;

    TRACEHANDLE m_hTrace;
};

VOID WINAPI _EventCallback(PEVENT_TRACE pEvent)
{
    // Skips the event if it is the event trace header. Log files contain this event
    // but real-time sessions do not. The event contains the same information as 
    // the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open 
    // the trace. 

    if (IsEqualGUID(pEvent->Header.Guid, EventTraceGuid) &&
        pEvent->Header.Class.Type == EVENT_TRACE_TYPE_INFO)
    {
        ; // Skip this event.
    }
    else
    {
        if (IsEqualGUID(CategoryGuid_Test, pEvent->Header.Guid))
        {
            // This example assumes that the start and end events are paired.
            // If this is the start event type, retrieve the start time values from the 
            // event; otherwise, retrieve the end time values from the event.

            if (pEvent->Header.Class.Type != EVENT_TYPE_TEST)
            {
                return ;
            }

            EVENT_DATA data;
            DWORD dwDataSize = sizeof(data);
            PBYTE pEventData = NULL;
            DWORD dwSize = pEvent->MofLength / dwDataSize;
            pEventData = (PBYTE)(pEvent->MofData);
            for (DWORD i = 0; i < dwSize; i++)
            {
                memcpy((void*)&data, pEventData+i*dwDataSize, dwDataSize);
                wprintf(L"consume size=%d,signature=%s \n", data.Size, data.Signature);
            }
        }
    }
}

void WINAPI _EventRecordCallback(PEVENT_RECORD pEventRecord)
{
    ((ETWConsumer*)(pEventRecord->UserContext))->EventRecordCallback(pEventRecord);
}