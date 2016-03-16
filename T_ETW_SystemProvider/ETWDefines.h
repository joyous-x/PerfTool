#pragma once
#include <Windows.h>


#define SESSION_GUID    SystemTraceControlGuid
#define SESSION_NAME    KERNEL_LOGGER_NAME

/*
class EventTrace
{
    uint16 EventSize;
    uint16 ReservedHeaderField;
    uint8  EventType;
    uint8  TraceLevel;
    uint16 TraceVersion;
    uint64 ThreadId;
    uint64 TimeStamp;
    uint8  EventGuid[];
    uint32 KernelTime;
    uint32 UserTime;
    uint32 InstanceId;
    uint8  ParentGuid[];
    uint32 ParentInstanceId;
    uint32 MofData;
    uint32 MofLength;
};

[Guid("{9e814aad-3204-11d2-9a82-006008a86939}")]
class MSNT_SystemTrace : EventTrace
{
    uint32 Flags;
};

[Guid("{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}"), EventVersion(3)]
class Process : MSNT_SystemTrace
{
};

[Guid("{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}"), EventVersion(2)]
class Image : MSNT_SystemTrace
{
};
*/

// 9e814aad-3204-11d2-9a82-006008a86939

[uuid("{9e814aad-3204-11d2-9a82-006008a86939}")]
class EVENT_MSNT_SystemTrace
{
};

[uuid("{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}")]
class EVENT_GUID_PROCESS
{
};

[uuid("{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}")]
class EVENT_GUID_IMAGE_LOAD
{
};

#define uint16 UINT16
#define uint8  UINT8
#define uint32 UINT32
#define uint64 UINT64
