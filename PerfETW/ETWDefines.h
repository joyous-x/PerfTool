#pragma once
#include <Windows.h>

#define uint16 UINT16
#define uint8  UINT8
#define uint32 UINT32
#define uint64 UINT64

#define SESSION_GUID    SystemTraceControlGuid
#define SESSION_NAME    KERNEL_LOGGER_NAME
#define SESSION_ENABLE_FLAGS    (EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_IMAGE_LOAD)

//> the guid of MSNT_SystemTrace is SystemTraceControlGuid
#define MSNT_SystemTrace SystemTraceControlGuid

DEFINE_GUID ( /* 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c */ 
             ProcessGuid, 
             0x3d6fa8d0, 
             0xfe05, 
             0x11d0, 
             0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c 
             );
DEFINE_GUID ( /* 2cb15d1d-5fc1-11d2-abe1-00a0c911f518 */ 
             ImageLoadGuid, 
             0x2cb15d1d, 
             0x5fc1, 
             0x11d2, 
             0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18 
             );


typedef struct _st_provider_filter
{
    GUID    EventClass;
    DWORD   dwActionStart;
    DWORD   dwActionEnd;
    const wchar_t* pcwcsPropertyNames[5];
}st_provider_filter;

extern st_provider_filter processfilter;
extern st_provider_filter imagefilter;