#pragma once

class _ST_PropertyData
{
public:
    ~_ST_PropertyData()
    {
        if (this->pData) free(pData), pData = NULL;
        if (this->pMapInfo) free(pMapInfo), pMapInfo = NULL;
    }

    std::wstring    wstrName;
    USHORT          uInType;
    USHORT          uOutType;
    PBYTE           pData;
    DWORD           dwDataSize;
    PEVENT_MAP_INFO pMapInfo;

    BOOL            bIsStruct;
    USHORT          uStructIndex;
    USHORT          uIndexStructStart;
    USHORT          uIndexStructEnd;
};
typedef _ST_PropertyData STPropertyData;

namespace ETWUtil
{
DWORD GetTraceEventInfo(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO &pInfo) 
{
    DWORD status = ERROR_SUCCESS;
    DWORD BufferSize = 0;
    PTRACE_EVENT_INFO pInfoTmp = NULL;

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

    pInfo = pInfoTmp;
    status = ERROR_SUCCESS;
Exit0:
    return status;
}

void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
    SIZE_T ByteLength = 0;
    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
    {
        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
    }
}

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

DWORD GetArraySizeofPropertyElement(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT uIndex, PUSHORT ArraySize)
{
    DWORD status = ERROR_SUCCESS;
    if ((pInfo->EventPropertyInfoArray[uIndex].Flags & PropertyParamCount) == PropertyParamCount)
    {
        DWORD Count = 0; // Expects the count to be defined by a UINT16 or UINT32
        DWORD PropertySize = 0;
        DWORD j = pInfo->EventPropertyInfoArray[uIndex].countPropertyIndex;

        PROPERTY_DATA_DESCRIPTOR DataDescriptor;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
        *ArraySize = (USHORT)Count;
    }
    else
    {
        *ArraySize = pInfo->EventPropertyInfoArray[uIndex].count;
    }

    return status;
}

//> 对属性 pInfo[uIndexInInfo] 按照格式：Type name[uIndexInPropertyElement] 进行解析
//> A、数组长度(非数组时，当成长度为1的数组)，函数：GetArraySize 取得
//> B、看 Type 是否是结构体
//> C、如果是结构体，则开始解析这个结构体的成员。此时需要指定：
//>    pStructName(即name)、uStructIndex(即uIndexInPropertyElement)
//>
//> 可以通过 FormatAndPrintData、PrintMapString 格式化 pPropertyData 中的数据
DWORD GetEventInfoProperty(
    PEVENT_RECORD pEvent, 
    PTRACE_EVENT_INFO   pInfo,
    USHORT              uIndexInInfo, 
    USHORT              uIndexInPropertyElement,
    LPCWSTR             pStructName, 
    USHORT              uStructIndex,
    STPropertyData*     pPropertyData)
{
    DWORD status = ERROR_SUCCESS;
    DWORD i = uIndexInInfo;
    DWORD j = uIndexInPropertyElement;
    std::wstring wstrPropertyName = (LPWSTR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
    {
        DWORD cur = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex;
        DWORD end = cur + pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;
        pPropertyData->wstrName = wstrPropertyName;
        pPropertyData->bIsStruct = TRUE;
        pPropertyData->uStructIndex = uIndexInPropertyElement;
        pPropertyData->uIndexStructEnd = end;
        pPropertyData->uIndexStructStart = cur;
        pPropertyData->pData = 0;
        pPropertyData->uInType = 0;
        pPropertyData->uOutType = 0;
        pPropertyData->dwDataSize = 0;
        pPropertyData->pMapInfo = 0;
        return ERROR_SUCCESS;
    }

    PBYTE        pData = NULL;
    DWORD        dwPropertySize = 0;
    ULONG        dwDescriptorsCount = 0;
    PROPERTY_DATA_DESCRIPTOR DataDescriptors[2];
    ZeroMemory(&DataDescriptors, sizeof(DataDescriptors));
    PEVENT_MAP_INFO pMapInfo = NULL;

    USHORT uInType = pInfo->EventPropertyInfoArray[i].nonStructType.InType;
    USHORT uOutType = pInfo->EventPropertyInfoArray[i].nonStructType.OutType;
    if (TDH_INTYPE_BINARY == uInType && TDH_OUTTYPE_IPV6 == uOutType)
    {
        status = ERROR_EVT_INVALID_EVENT_DATA;
        goto cleanup;
    }

    if (pStructName)
    {
        DataDescriptors[0].PropertyName = (ULONGLONG)pStructName;
        DataDescriptors[0].ArrayIndex = uStructIndex;
        DataDescriptors[1].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
        DataDescriptors[1].ArrayIndex = j;
        dwDescriptorsCount = 2;
    }
    else
    {
        DataDescriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
        DataDescriptors[0].ArrayIndex = j;
        dwDescriptorsCount = 1;
    }

    status = TdhGetPropertySize(pEvent, 0, NULL, dwDescriptorsCount, &DataDescriptors[0], &dwPropertySize);
    if (ERROR_SUCCESS != status) goto cleanup;

    pData = (PBYTE)malloc(dwPropertySize);
    if (NULL == pData) 
    {
        status = ERROR_OUTOFMEMORY;
        goto cleanup;
    }

    status = TdhGetProperty(pEvent, 0, NULL, dwDescriptorsCount, &DataDescriptors[0], dwPropertySize, pData);
    if (ERROR_SUCCESS != status) goto cleanup;

    PWCHAR pwcsMapName = (PWCHAR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset);
    status = GetMapInfo(pEvent, pwcsMapName, pInfo->DecodingSource, pMapInfo);
    if (ERROR_SUCCESS != status) goto cleanup;

    pPropertyData->wstrName = wstrPropertyName;
    pPropertyData->uInType = uInType;
    pPropertyData->uOutType = uOutType;
    pPropertyData->dwDataSize = dwPropertySize;
    pPropertyData->pData = pData;
    pPropertyData->pMapInfo = pMapInfo;
    pPropertyData->bIsStruct = FALSE;
    pPropertyData->uStructIndex = 0;
    pPropertyData->uIndexStructEnd = 0;
    pPropertyData->uIndexStructStart = 0;

cleanup:
    if (ERROR_SUCCESS != status)
    {
        if (pData) free(pData);
        if (pMapInfo) free(pMapInfo);
    }

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

#define MAX_NAME 256
DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo, DWORD dwPointSize)
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
            typedef LPTSTR (NTAPI *PIPV6ADDRTOSTRING)(
                const IN6_ADDR *Addr,
                LPTSTR S
                );

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
            if (4 == dwPointSize)
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

                pData += dwPointSize * 2;

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


} //> end of namespace