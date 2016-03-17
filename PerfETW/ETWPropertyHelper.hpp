#pragma once

#include <map>
#include "ETWUtil.h"
#include "ETWDefines.h"

/************************************************************************/
typedef struct _st_provider_filter
{
    DWORD   dwEventType;
    GUID    EventClass;
    DWORD   dwActionStart;
    DWORD   dwActionEnd;
    DWORD   dwPropertyNum;
    const wchar_t* pcwcsPropertyNames[5];
}st_provider_filter;

#define event_type__process (1)
#define event_type__image   (2)

st_provider_filter filters[] = 
{
    {
        event_type__process,
        ProcessGuid, 
        EVENT_TRACE_TYPE_START,
        EVENT_TRACE_TYPE_END,
        4,
        {L"ProcessID", L"ApplicationID", L"ImageFileName", L"CommandLine"}
    },
    {
        event_type__image,
        ImageLoadGuid, 
        EVENT_TRACE_TYPE_LOAD,
        EVENT_TRACE_TYPE_END,
        3,
        {L"ProcessID", L"ImageSize", L"FileName"}
    }
};
DWORD numFilters = sizeof(filters) / sizeof(filters[0]);

/************************************************************************/
#define action_type__start (1)
#define action_type__end   (2)

class EventData
{
public:
    DWORD dwPointerSize;
    DWORD dwEventType; 
    DWORD dwActionType;
    std::wstring wstrStringOnly;

    struct ST_IMAGE_INFO
    {
        DWORD   dwProcID;
        DWORD   dwImageSize;
        std::wstring wstrImageName;
    } image;
    struct ST_PROCESS_INFO
    {
        DWORD   dwProcID;
        DWORD   dwApplicationID;
        std::wstring wstrCommandLine;
        std::wstring wstrImageName;
    } proc;
};
/************************************************************************/

class ETWPropertyHelper
{
public:
    ETWPropertyHelper(PEVENT_RECORD pEvent) : m_pEvent(pEvent), m_pInfo(0), m_dwPointerSize(4), m_pFilter(NULL)
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

        if (m_dwPointerSize != 4) 
        {
            //> 暂时不处理 8bytes 指针
            return FALSE;
        }

        st_provider_filter* pFilter = NULL; 
        for (DWORD i = 0; i < numFilters; i++)
        {
            if (0 == IsEqualGUID(pEvent->EventHeader.ProviderId, filters[i].EventClass))
            {
                continue;
            }

            pFilter = &filters[i];
            break;
        }

        if (NULL == pFilter)
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
            pData->dwEventType  = pFilter->dwEventType;
        }

        m_pFilter = pFilter;
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
            if (0 == IsTargetProperty(m_pInfo, i, pData)) continue;

            USHORT uArraySize = 0;
            ETWUtil::GetArraySizeofPropertyElement(pEvent, m_pInfo, i, &uArraySize);
            for (USHORT u = 0; u < 1/*uArraySize*/; u++)
            {
                STPropertyData stPropertyData;
                dwStatus = ETWUtil::GetEventInfoProperty(pEvent, m_pInfo, i, u, NULL, 0, &stPropertyData);
                if (ERROR_SUCCESS != dwStatus || stPropertyData.bIsStruct) continue;
                TranslatePropertyData(&stPropertyData, pData);
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
        ULONGLONG Nanoseconds = (m_pEvent->EventHeader.TimeStamp.QuadPart % 10000000) * 100;

        wprintf(L"%02d/%02d/%02d %02d:%02d:%02d.%I64u\n", 
            stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wSecond, Nanoseconds);

        return Nanoseconds;
    }

private:
    DWORD IsTargetProperty(PTRACE_EVENT_INFO pInfo, DWORD dwIndex, EventData* pData)
    {
        std::wstring wstrPropertyName = (LPWSTR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[dwIndex].NameOffset);

        for (DWORD i = 0; m_pFilter && i < m_pFilter->dwPropertyNum; i++)
        {
            if (wcsicmp(wstrPropertyName.c_str(), m_pFilter->pcwcsPropertyNames[i])) continue;
            return 1;
        }

        return 0;
    }

    DWORD TranslatePropertyData(STPropertyData* ori, EventData* pData)
    {
        if (pData->dwEventType == event_type__process)
        {
            if (0 == wcsicmp(ori->wstrName.c_str(), m_pFilter->pcwcsPropertyNames[0]))
            {
                pData->proc.dwProcID = *(DWORD*)(ori->pData);
            }
            else if (0 == wcsicmp(ori->wstrName.c_str(), m_pFilter->pcwcsPropertyNames[1]))
            {
                pData->proc.dwApplicationID = *(DWORD*)(ori->pData);
            }
            else if (0 == wcsicmp(ori->wstrName.c_str(), m_pFilter->pcwcsPropertyNames[2]))
            {
                pData->proc.wstrImageName = (const wchar_t*)(ori->pData);
            }
            else if (0 == wcsicmp(ori->wstrName.c_str(), m_pFilter->pcwcsPropertyNames[3]))
            {
                pData->proc.wstrCommandLine = (const wchar_t*)(ori->pData);
            }
        }
        else if (pData->dwEventType == event_type__image)
        {
            if (0 == wcsicmp(ori->wstrName.c_str(), m_pFilter->pcwcsPropertyNames[0]))
            {
                pData->image.dwProcID = *(DWORD*)(ori->pData);
            }
            else if (0 == wcsicmp(ori->wstrName.c_str(), m_pFilter->pcwcsPropertyNames[1]))
            {
                pData->image.dwImageSize = *(DWORD*)(ori->pData);
            }
            else if (0 == wcsicmp(ori->wstrName.c_str(), m_pFilter->pcwcsPropertyNames[2]))
            {
                pData->image.wstrImageName = (const wchar_t*)(ori->pData);
            }
        }
        return 0;
    }

private:
    DWORD               m_dwPointerSize;
    PEVENT_RECORD       m_pEvent;
    PTRACE_EVENT_INFO   m_pInfo;
    st_provider_filter* m_pFilter; 
};