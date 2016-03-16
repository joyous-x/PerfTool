#pragma once

class ETWPropertyHelper
{
public:
    ETWPropertyHelper(PEVENT_RECORD pEvent) : m_pEvent(pEvent), m_pInfo(0), m_dwPointerSize(4)
    {
        if (NULL == pEvent)
        {
            return ;
        }

        if (EVENT_HEADER_FLAG_64_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
        {
            m_dwPointerSize  = 8;
        }
    }

    ~ETWPropertyHelper()
    {
        if (m_pInfo)
        {
            free(m_pInfo), m_pInfo = NULL;
        }
    }

    DWORD GetTraceEventInfo(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO &pInfo) 
    {
        DWORD status = ERROR_SUCCESS;
        DWORD BufferSize = 0;
        PTRACE_EVENT_INFO pInfoTmp = NULL;

        if (m_pInfo)
        {
            free(m_pInfo), m_pInfo = NULL;
        }

        status = TdhGetEventInformation(pEvent, 0, NULL, pInfoTmp, &BufferSize);
        if (ERROR_INSUFFICIENT_BUFFER != status)
        {
            goto Exit0;
        }

        pInfoTmp = (TRACE_EVENT_INFO*) malloc(BufferSize);
        if (pInfoTmp == NULL)
        {
            status = ERROR_OUTOFMEMORY;
            goto Exit0;
        }

        status = TdhGetEventInformation(pEvent, 0, NULL, pInfoTmp, &BufferSize);
        if (ERROR_SUCCESS != status)
        {
            free(pInfoTmp);
            goto Exit0;
        }

        m_pInfo = pInfoTmp;
        status = ERROR_SUCCESS;
Exit0:
        pInfo = m_pInfo;
        return status;
    }

    ULONGLONG GetTimeStamp( ) 
    {
        FILETIME ft;
        ft.dwHighDateTime = m_pEvent->EventHeader.TimeStamp.HighPart;
        ft.dwLowDateTime = m_pEvent->EventHeader.TimeStamp.LowPart;

        SYSTEMTIME st;
        SYSTEMTIME stLocal;
        FileTimeToSystemTime(&ft, &st);
        SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

        ULONGLONG Nanoseconds = (m_pEvent->EventHeader.TimeStamp.QuadPart % 10000000) * 100;
        wprintf(L"%02d/%02d/%02d %02d:%02d:%02d.%I64u\n", 
            stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wSecond, Nanoseconds);

        return Nanoseconds;
    }

private:
    PEVENT_RECORD       m_pEvent;
    PTRACE_EVENT_INFO   m_pInfo;
    DWORD               m_dwPointerSize;
};