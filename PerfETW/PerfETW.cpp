// ETW.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "ETWConsumer.hpp"
#include "ETWController.hpp"

st_provider_filter processfilter = 
{
    ProcessGuid, 
    EVENT_TRACE_TYPE_START,
    EVENT_TRACE_TYPE_END,
    {L"ProcessID", L"ProcessID"}
};

st_provider_filter imagefilter = 
{
    ImageLoadGuid, 
    EVENT_TRACE_TYPE_LOAD,
    EVENT_TRACE_TYPE_END,
    {L"ProcessID", L"FileName", L"ImageBase", L"ImageSize"}
};

int _tmain(int argc, _TCHAR* argv[])
{
    DWORD dwRet = 0;
    ETWConsumer consumer;
    ETWController controller(SESSION_GUID);

//     The NT Kernel Logger session is an event tracing session
//     that records a predefined set of kernel events. You do not 
//     call the EnableTrace function to enable the kernel providers.
//     Instead, you use the EnableFlags member of EVENT_TRACE_PROPERTIES 
//     structure to specify the kernel events that you want to receive.
//     The StartTrace function uses the enable flags that you specify 
//     to enable the kernel providers.
    if (ERROR_ALREADY_EXISTS == controller.StartTrace())
    {
        if (0 != controller.StopTrace())
        {
            
        }

        if (0 != controller.StartTrace())
        {
            goto Exit0;
        }
    }

    dwRet = consumer.OpenTrace();
    if (0 != dwRet)
    {
        goto Exit0;
    }

    for (int i = 0; ; i++)
    {
        Sleep(6000);
    }

    dwRet = consumer.CloseTrace();
Exit0:
    controller.StopTrace();
	return 0;
}
