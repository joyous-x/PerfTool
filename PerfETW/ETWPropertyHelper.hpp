#pragma once

#include <map>
#include "ETWUtil.h"
#include "ETWDefines.h"


#define event_type__process (1)
#define event_type__image   (2)

#define action_type__start (1)
#define action_type__end   (2)

struct EventData
{
    DWORD dwEventType; 
    DWORD dwActionType;
    DWORD dwPointerSize;
    std::map<std::wstring, BYTE*> mapProperty;
    std::wstring wstrStringOnly;
};

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

    BOOL IsTargetEvent(PEVENT_RECORD pEvent, EventData* pData)
    {
        EventData tmp;

        st_provider_filter* pFilter = NULL; 
        if (IsEqualGUID(pEvent->EventHeader.ProviderId, processfilter.EventClass))
        {
            pFilter = &processfilter;
            tmp.dwEventType = event_type__process;
        }
        else if (IsEqualGUID(pEvent->EventHeader.ProviderId, imagefilter.EventClass))
        {
            pFilter = &imagefilter;
            tmp.dwEventType = event_type__image;
        }
        else 
        {
            return FALSE;
        }

        if (pEvent->EventHeader.EventDescriptor.Opcode == pFilter->dwActionEnd)
        {
            tmp.dwActionType = action_type__end;
        }
        else if (pEvent->EventHeader.EventDescriptor.Opcode == pFilter->dwActionStart)
        {
            tmp.dwActionType = action_type__start;
        }
        else
        {
            return FALSE;
        }

        ETWUtil::GetTraceEventInfo(pEvent, m_pInfo);
        if (DecodingSourceWbem != m_pInfo->DecodingSource)  // MOF class
        {
            //> 暂时只处理 MOF
            return FALSE;
        }

        if (pData)
        {
            pData->dwActionType = tmp.dwActionType;
            pData->dwEventType  = tmp.dwEventType;
        }

        return TRUE;
    }

    DWORD GetToplevelPropertys(PEVENT_RECORD pEvent, EventData* pData)
    {
        pData->dwPointerSize = m_dwPointerSize;
        if (EVENT_HEADER_FLAG_STRING_ONLY == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY))
        {
            pData->wstrStringOnly = (LPWSTR)pEvent->UserData;
            return ERROR_SUCCESS;
        }

        DWORD dwStatus = ERROR_SUCCESS;
        for (USHORT i =0; i < m_pInfo->TopLevelPropertyCount; i++)
        {
            USHORT uArraySize = 0;
            ETWUtil::GetArraySizeofPropertyElement(pEvent, m_pInfo, i, &uArraySize);
            for (USHORT u = 0; u < 1/*uArraySize*/; u++)
            {
                STPropertyData stPropertyData;
                dwStatus = ETWUtil::GetEventInfoProperty(pEvent, m_pInfo, i, u, NULL, 0, &stPropertyData);
                // if (ERROR_SUCCESS != status) goto cleanup;
                if (stPropertyData.bIsStruct) continue;
                pData->mapProperty[stPropertyData.wstrName] = stPropertyData.pData;
                wprintf(L"%s ", stPropertyData.wstrName.c_str());
            }
        }

        return ERROR_SUCCESS;
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
        ULONGLONG Nanoseconds = (m_pEvent->EventHeader.TimeStamp.QuadPart % 10000000) * 100;;

        wprintf(L"%02d/%02d/%02d %02d:%02d:%02d.%I64u\n", 
            stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wSecond, Nanoseconds);

        return Nanoseconds;
    }

private:
    


private:
    DWORD               m_dwPointerSize;
    PEVENT_RECORD       m_pEvent;
    PTRACE_EVENT_INFO   m_pInfo;
};