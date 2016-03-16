#pragma once

typedef struct _ST_PropertyData
{
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
}STPropertyData;

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


} //> end of namespace