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

void WINAPI _EventCallback(PEVENT_TRACE pEvent);
void WINAPI _EventRecordCallback(PEVENT_RECORD pEventRecord);

DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo);
DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPCWSTR pStructureName, USHORT StructIndex);
DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo); 
void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo);
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);

typedef LPTSTR (NTAPI *PIPV6ADDRTOSTRING)(
    const IN6_ADDR *Addr,
    LPTSTR S
    );

#define MAX_NAME 256
DWORD g_PointerSize = 0;

class ETWConsumer
{
public:
    ETWConsumer() : m_TimerResolution(0), m_hTrace(0)
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
        PTRACE_EVENT_INFO pInfo = NULL;
        ETWPropertyHelper etwHelper(pEvent);

        if (FALSE == IsTargetEvent(pEvent, pInfo))
        {
            goto cleanup;
        }

        etwHelper.GetTraceEventInfo(pEvent, pInfo);
        if (DecodingSourceWbem != pInfo->DecodingSource)  // MOF class
        {
            //> 暂时只处理 MOF
            goto cleanup;
        }

        PrintHead(pEvent);

        g_PointerSize  = 4;
        if (EVENT_HEADER_FLAG_64_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
        {
            g_PointerSize  = 8;
        }

        if (EVENT_HEADER_FLAG_STRING_ONLY == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY))
        {
            wprintf(L"%s\n", (LPWSTR)pEvent->UserData);
            goto cleanup;
        }

        for (USHORT i =0; i < pInfo->TopLevelPropertyCount; i++)
        {
            status = PrintProperties(pEvent, pInfo, i, NULL, 0);
            // if (ERROR_SUCCESS != status) goto cleanup;
        }

cleanup:
        return status;
    }

private:
    BOOL IsTargetEvent(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo) 
    {
        BOOL bRet = FALSE;
        const DWORD EVENT_PROCESS = 1;
        const DWORD EVENT_IMAGE_LOAD = 2;
        DWORD dwType = EVENT_PROCESS;

        if (NULL == pEvent)
        {
            goto Exit0;
        }

        if (!IsEqualGUID(pEvent->EventHeader.ProviderId, _uuidof(EVENT_MSNT_SystemTrace)))
        {
            // printf("i am not really provider GUID \n");
        }

        if (IsEqualGUID(pEvent->EventHeader.ProviderId, _uuidof(EVENT_GUID_PROCESS)))
        {
            dwType = EVENT_PROCESS;
        }
        else if (IsEqualGUID(pEvent->EventHeader.ProviderId, _uuidof(EVENT_GUID_IMAGE_LOAD)))
        {
            dwType = EVENT_IMAGE_LOAD;
        }
        else 
        {
            goto Exit0;
        }

        if (pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_END && dwType == EVENT_IMAGE_LOAD)
        {
            goto Exit0;
        }

        if (pEvent->EventHeader.EventDescriptor.Opcode != EVENT_TRACE_TYPE_START &&
            pEvent->EventHeader.EventDescriptor.Opcode != EVENT_TRACE_TYPE_END &&
            pEvent->EventHeader.EventDescriptor.Opcode != EVENT_TRACE_TYPE_LOAD)
        {
            goto Exit0;
        }

        if (NULL == pInfo)
        {
            bRet = TRUE;
            goto Exit0;
        }

        //>
        //> 为了更清楚的了解pEvent->EventHeader.ProviderId 和 pInfo->ProviderGuid 的区别
        //> 
        if (!IsEqualGUID(pInfo->ProviderGuid, _uuidof(EVENT_MSNT_SystemTrace)))
        {
            goto Exit0;
        }

        if (!IsEqualGUID(pInfo->EventGuid, _uuidof(EVENT_GUID_PROCESS)) && 
            !IsEqualGUID(pInfo->EventGuid, _uuidof(EVENT_GUID_IMAGE_LOAD)))
        {
            goto Exit0;
        }

        bRet = TRUE;
Exit0:
        return bRet;
    }

    void PrintHead(PEVENT_RECORD pEvent) 
    {
        std::wstring wstrHead = L"--";

        if (IsEqualGUID(pEvent->EventHeader.ProviderId, _uuidof(EVENT_GUID_PROCESS)))
        {
            wstrHead += L"EVENT_PROCESS";
        }
        else if (IsEqualGUID(pEvent->EventHeader.ProviderId, _uuidof(EVENT_GUID_IMAGE_LOAD)))
        {
            wstrHead += L"EVENT_IMAGE_LOAD";
        }
        else 
        {
            return ;
        }

        wstrHead += L" Action:";
        if (pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_START)
        {
            wstrHead += L"Start";
        }
        else if (pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_END)
        {
            wstrHead += L"Stop";
        }
        else if (pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_LOAD)
        {
            wstrHead += L"Load";
        }
        else
        {
            wstrHead += L"Unknown";
        }

        wprintf(L"%s ", wstrHead.c_str());
    }
private:
    // Used to calculate CPU usage
    ULONG m_TimerResolution;

    TRACEHANDLE m_hTrace;
};

void WINAPI _EventRecordCallback(PEVENT_RECORD pEventRecord)
{
    ((ETWConsumer*)(pEventRecord->UserContext))->EventRecordCallback(pEventRecord);
}

DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPCWSTR pStructureName, USHORT StructIndex)
{
    DWORD status = ERROR_SUCCESS;
    DWORD LastMember = 0;  // Last member of a structure
    USHORT ArraySize = 0;
    PEVENT_MAP_INFO pMapInfo = NULL;
    PROPERTY_DATA_DESCRIPTOR DataDescriptors[2];
    ULONG DescriptorsCount = 0;
    PBYTE pData = NULL;

    EVENT_PROPERTY_INFO& stEventPropertyInfo = pInfo->EventPropertyInfoArray[i];
    DWORD        dwPropertySize = 0;
    std::wstring wstrPropertyName = (LPWSTR)((PBYTE)(pInfo) + stEventPropertyInfo.NameOffset);

    wprintf(L"\t %s ", wstrPropertyName.c_str()); 

    status = GetArraySize(pEvent, pInfo, i, &ArraySize);
    for (USHORT k = 0; k < ArraySize; k++)
    {
        if ((stEventPropertyInfo.Flags & PropertyStruct) == PropertyStruct)
        {
            DWORD end = stEventPropertyInfo.structType.StructStartIndex + stEventPropertyInfo.structType.NumOfStructMembers;
            for (USHORT cur = stEventPropertyInfo.structType.StructStartIndex; cur < end; cur++)
            {
                status = PrintProperties(pEvent, pInfo, cur, wstrPropertyName.c_str(), k);
                if (ERROR_SUCCESS != status)
                {
                    continue;
                }
            }

            continue;
        }

        ZeroMemory(&DataDescriptors, sizeof(DataDescriptors));
        USHORT uInType = pInfo->EventPropertyInfoArray[i].nonStructType.InType;
        USHORT uOutType = pInfo->EventPropertyInfoArray[i].nonStructType.OutType;

        // The TDH API does not support IPv6 addresses. If the output type is TDH_OUTTYPE_IPV6,
        // you will not be able to consume the rest of the event. If you try to consume the
        // remainder of the event, you will get ERROR_EVT_INVALID_EVENT_DATA.
        if (TDH_INTYPE_BINARY == uInType && TDH_OUTTYPE_IPV6 == uOutType)
        {
            status = ERROR_EVT_INVALID_EVENT_DATA;
            goto cleanup;
        }

        // To retrieve a member of a structure, you need to specify an array of descriptors. 
        // The first descriptor in the array identifies the name of the structure and the second 
        // descriptor defines the member of the structure whose data you want to retrieve. 
        if (pStructureName)
        {
            DataDescriptors[0].PropertyName = (ULONGLONG)pStructureName;
            DataDescriptors[0].ArrayIndex = StructIndex;
            DataDescriptors[1].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
            DataDescriptors[1].ArrayIndex = k;
            DescriptorsCount = 2;
        }
        else
        {
            DataDescriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
            DataDescriptors[0].ArrayIndex = k;
            DescriptorsCount = 1;
        }

        status = TdhGetPropertySize(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], &dwPropertySize);
        if (ERROR_SUCCESS != status) goto cleanup;

        pData = (PBYTE)malloc(dwPropertySize);
        if (NULL == pData) 
        {
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        status = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], dwPropertySize, pData);
        if (ERROR_SUCCESS != status) goto cleanup;

        // Get the name/value mapping if the property specifies a value map.
        PWCHAR pwcsMapName = (PWCHAR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset);
        status = GetMapInfo(pEvent, pwcsMapName, pInfo->DecodingSource, pMapInfo);
        if (ERROR_SUCCESS != status) goto cleanup;

        status = FormatAndPrintData(pEvent, uInType, uOutType, pData, dwPropertySize, pMapInfo);
        if (ERROR_SUCCESS != status) goto cleanup;
cleanup:
        if (pData)
        {
            free(pData);
            pData = NULL;
        }

        if (pMapInfo)
        {
            free(pMapInfo);
            pMapInfo = NULL;
        }
    }

Exit0:
    if (pData)
    {
        free(pData);
        pData = NULL;
    }

    if (pMapInfo)
    {
        free(pMapInfo);
        pMapInfo = NULL;
    }

    return status;
}


DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo)
{
    UNREFERENCED_PARAMETER(pEvent);

    DWORD status = ERROR_SUCCESS;

    switch (InType)
    {
    case TDH_INTYPE_UNICODESTRING:
    case TDH_INTYPE_COUNTEDSTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
    case TDH_INTYPE_NONNULLTERMINATEDSTRING:
        {
            size_t StringLength = 0;

            if (TDH_INTYPE_COUNTEDSTRING == InType)
            {
                StringLength = *(PUSHORT)pData;
            }
            else if (TDH_INTYPE_REVERSEDCOUNTEDSTRING == InType)
            {
                StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
            }
            else if (TDH_INTYPE_NONNULLTERMINATEDSTRING == InType)
            {
                StringLength = DataSize;
            }
            else
            {
                StringLength = wcslen((LPWSTR)pData);
            }

            wprintf(L"%.*s\n", StringLength, (LPWSTR)pData);
            break;
        }

    case TDH_INTYPE_ANSISTRING:
    case TDH_INTYPE_COUNTEDANSISTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
    case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
        {
            size_t StringLength = 0;

            if (TDH_INTYPE_COUNTEDANSISTRING == InType)
            {
                StringLength = *(PUSHORT)pData;
            }
            else if (TDH_INTYPE_REVERSEDCOUNTEDANSISTRING == InType)
            {
                StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
            }
            else if (TDH_INTYPE_NONNULLTERMINATEDANSISTRING == InType)
            {
                StringLength = DataSize;
            }
            else
            {
                StringLength = strlen((LPSTR)pData);
            }

            wprintf(L"%.*S\n", StringLength, (LPSTR)pData);
            break;
        }

    case TDH_INTYPE_INT8:
        {
            wprintf(L"%hd\n", *(PCHAR)pData);
            break;
        }
    case TDH_INTYPE_UINT8:
        {
            if (TDH_OUTTYPE_HEXINT8 == OutType)
            {
                wprintf(L"0x%x\n", *(PBYTE)pData);
            }
            else
            {
                wprintf(L"%hu\n", *(PBYTE)pData);
            }

            break;
        }

    case TDH_INTYPE_INT16:
        {
            wprintf(L"%hd\n", *(PSHORT)pData);
            break;
        }

    case TDH_INTYPE_UINT16:
        {
            if (TDH_OUTTYPE_HEXINT16 == OutType)
            {
                wprintf(L"0x%x\n", *(PUSHORT)pData);
            }
            else if (TDH_OUTTYPE_PORT == OutType)
            {
                wprintf(L"%hu\n", ntohs(*(PUSHORT)pData));
            }
            else
            {
                wprintf(L"%hu\n", *(PUSHORT)pData);
            }

            break;
        }

    case TDH_INTYPE_INT32:
        {
            if (TDH_OUTTYPE_UNSIGNEDINT == OutType)
            {
                wprintf(L"0x%x\n", *(PLONG)pData);
            }
            else
            {
                wprintf(L"%d\n", *(PLONG)pData);
            }

            break;
        }

    case TDH_INTYPE_UINT32:
        {
            if (TDH_OUTTYPE_UNSIGNEDINT == OutType ||
                TDH_OUTTYPE_HEXINT32 == OutType)
            {
                wprintf(L"0x%x\n", *(PULONG)pData);
            }
            else if (TDH_OUTTYPE_IPV4 == OutType)
            {
                wprintf(L"%d.%d.%d.%d\n", (*(PLONG)pData >>  0) & 0xff,
                    (*(PLONG)pData >>  8) & 0xff,
                    (*(PLONG)pData >>  16) & 0xff,
                    (*(PLONG)pData >>  24) & 0xff);
            }
            else
            {
                if (pMapInfo)
                {
                    PrintMapString(pMapInfo, pData);
                }
                else
                {
                    wprintf(L"%lu\n", *(PULONG)pData);
                }
            }

            break;
        }

    case TDH_INTYPE_INT64:
        {
            wprintf(L"%I64d\n", *(PLONGLONG)pData);

            break;
        }

    case TDH_INTYPE_UINT64:
        {
            if (TDH_OUTTYPE_HEXINT64 == OutType)
            {
                wprintf(L"0x%x\n", *(PULONGLONG)pData);
            }
            else
            {
                wprintf(L"%I64u\n", *(PULONGLONG)pData);
            }

            break;
        }

    case TDH_INTYPE_FLOAT:
        {
            wprintf(L"%f\n", *(PFLOAT)pData);

            break;
        }

    case TDH_INTYPE_DOUBLE:
        {
            wprintf(L"%I64f\n", *(DOUBLE*)pData);

            break;
        }

    case TDH_INTYPE_BOOLEAN:
        {
            wprintf(L"%s\n", (0 == (PBOOL)pData) ? L"false" : L"true");

            break;
        }

    case TDH_INTYPE_BINARY:
        {
            if (TDH_OUTTYPE_IPV6 == OutType)
            {
                WCHAR IPv6AddressAsString[46];
                PIPV6ADDRTOSTRING fnRtlIpv6AddressToString;

                fnRtlIpv6AddressToString = (PIPV6ADDRTOSTRING)GetProcAddress(
                    GetModuleHandle(L"ntdll"), "RtlIpv6AddressToStringW");

                if (NULL == fnRtlIpv6AddressToString)
                {
                    wprintf(L"GetProcAddress failed with %lu.\n", status = GetLastError());
                    goto cleanup;
                }

                fnRtlIpv6AddressToString((IN6_ADDR*)pData, IPv6AddressAsString);

                wprintf(L"%s\n", IPv6AddressAsString);
            }
            else
            {
                for (DWORD i = 0; i < DataSize; i++)
                {
                    wprintf(L"%.2x", pData[i]);
                }

                wprintf(L"\n");
            }

            break;
        }

    case TDH_INTYPE_GUID:
        {
            WCHAR szGuid[50];

            StringFromGUID2(*(GUID*)pData, szGuid, sizeof(szGuid)-1);
            wprintf(L"%s\n", szGuid);

            break;
        }

    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_SIZET:
        {
            if (4 == g_PointerSize)
            {
                wprintf(L"0x%x\n", *(PULONG)pData);
            }
            else
            {
                wprintf(L"0x%x\n", *(PULONGLONG)pData);
            }

            break;
        }

    case TDH_INTYPE_FILETIME:
        {
            break;
        }

    case TDH_INTYPE_SYSTEMTIME:
        {
            break;
        }

    case TDH_INTYPE_SID:
        {
            WCHAR UserName[MAX_NAME];
            WCHAR DomainName[MAX_NAME];
            DWORD cchUserSize = MAX_NAME;
            DWORD cchDomainSize = MAX_NAME;
            SID_NAME_USE eNameUse;

            if (!LookupAccountSid(NULL, (PSID)pData, UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
            {
                if (ERROR_NONE_MAPPED == status)
                {
                    wprintf(L"Unable to locate account for the specified SID\n");
                    status = ERROR_SUCCESS;
                }
                else
                {
                    wprintf(L"LookupAccountSid failed with %lu\n", status = GetLastError());
                }

                goto cleanup;
            }
            else
            {
                wprintf(L"%s\\%s\n", DomainName, UserName);
            }

            break;
        }

    case TDH_INTYPE_HEXINT32:
        {
            wprintf(L"0x%x\n", (PULONG)pData);
            break;
        }

    case TDH_INTYPE_HEXINT64:
        {
            wprintf(L"0x%x\n", (PULONGLONG)pData);
            break;
        }

    case TDH_INTYPE_UNICODECHAR:
        {
            wprintf(L"%c\n", *(PWCHAR)pData);
            break;
        }

    case TDH_INTYPE_ANSICHAR:
        {
            wprintf(L"%C\n", *(PCHAR)pData);
            break;
        }

    case TDH_INTYPE_WBEMSID:
        {
            WCHAR UserName[MAX_NAME];
            WCHAR DomainName[MAX_NAME];
            DWORD cchUserSize = MAX_NAME;
            DWORD cchDomainSize = MAX_NAME;
            SID_NAME_USE eNameUse;

            if ((PULONG)pData > 0)
            {
                // A WBEM SID is actually a TOKEN_USER structure followed 
                // by the SID. The size of the TOKEN_USER structure differs 
                // depending on whether the events were generated on a 32-bit 
                // or 64-bit architecture. Also the structure is aligned
                // on an 8-byte boundary, so its size is 8 bytes on a
                // 32-bit computer and 16 bytes on a 64-bit computer.
                // Doubling the pointer size handles both cases.

                pData += g_PointerSize * 2;

                if (!LookupAccountSid(NULL, (PSID)pData, UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
                {
                    if (ERROR_NONE_MAPPED == status)
                    {
                        wprintf(L"Unable to locate account for the specified SID\n");
                        status = ERROR_SUCCESS;
                    }
                    else
                    {
                        wprintf(L"LookupAccountSid failed with %lu\n", status = GetLastError());
                    }

                    goto cleanup;
                }
                else
                {
                    wprintf(L"%s\\%s\n", DomainName, UserName);
                }
            }

            break;
        }

    default:
        status = ERROR_NOT_FOUND;
    }

cleanup:

    return status;
}


void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData)
{
    BOOL MatchFound = FALSE;

    if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP) == EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP ||
        ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
        (pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) != EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
        {
            wprintf(L"%s\n", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[*(PULONG)pData].OutputOffset));
        }
        else
        {
            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if (pMapInfo->MapEntryArray[i].Value == *(PULONG)pData)
                {
                    wprintf(L"%s\n", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));
                    MatchFound = TRUE;
                    break;
                }
            }

            if (FALSE == MatchFound)
            {
                wprintf(L"%lu\n", *(PULONG)pData);
            }
        }
    }
    else if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_BITMAP) == EVENTMAP_INFO_FLAG_MANIFEST_BITMAP ||
        (pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_BITMAP) == EVENTMAP_INFO_FLAG_WBEM_BITMAP ||
        ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
        (pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) == EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
        {
            DWORD BitPosition = 0;

            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if ((*(PULONG)pData & (BitPosition = (1 << i))) == BitPosition)
                {
                    wprintf(L"%s%s", 
                        (MatchFound) ? L" | " : L"", 
                        (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));

                    MatchFound = TRUE;
                }
            }

        }
        else
        {
            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if ((pMapInfo->MapEntryArray[i].Value & *(PULONG)pData) == pMapInfo->MapEntryArray[i].Value)
                {
                    wprintf(L"%s%s", 
                        (MatchFound) ? L" | " : L"", 
                        (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));

                    MatchFound = TRUE;
                }
            }
        }

        if (MatchFound)
        {
            wprintf(L"\n");
        }
        else
        {
            wprintf(L"%lu\n", *(PULONG)pData);
        }
    }
}


// Get the size of the array. For MOF-based events, the size is specified in the declaration or using 
// the MAX qualifier. For manifest-based events, the property can specify the size of the array
// using the count attribute. The count attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size.
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
        *ArraySize = (USHORT)Count;
    }
    else
    {
        *ArraySize = pInfo->EventPropertyInfoArray[i].count;
    }

    return status;
}


// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.

DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD MapSize = 0;

    // Retrieve the required buffer size for the map info.
    status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pMapInfo = (PEVENT_MAP_INFO) malloc(MapSize);
        if (pMapInfo == NULL)
        {
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
    }

    if (ERROR_SUCCESS == status)
    {
        if (DecodingSourceXMLFile == DecodingSource)
        {
            RemoveTrailingSpace(pMapInfo);
        }
    }
    else if (ERROR_NOT_FOUND == status)
    {
        status = ERROR_SUCCESS; // This case is okay.
    }

cleanup:
    return status;
}


// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.

void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
    SIZE_T ByteLength = 0;
    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
    {
        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
    }
}
