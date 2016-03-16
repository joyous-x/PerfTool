// T_SelfProvider.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "ETWConsumer.hpp"
#include "ETWProvider.hpp"
#include "ETWController.hpp"

int _tmain(int argc, _TCHAR* argv[])
{
    DWORD dwRet = 0;
    ETWConsumer consumer;
    ETWController controller(ProviderGuid);
    ETWProvider provider;

    provider.RegisterTrace();
    if (ERROR_ALREADY_EXISTS == controller.StartTrace())
    {
        if (0 != controller.StopTrace(provider.GetSessionHandle()))
        {
            goto Exit0;
        }

        if (0 != controller.StartTrace())
        {
            goto Exit0;
        }
    }

    dwRet = controller.EnableTrace(1,5);
    if (0 != dwRet)
    {
        goto Exit0;
    }

    dwRet = consumer.OpenTrace();
    if (0 != dwRet)
    {
        goto Exit0;
    }

    for (int i = 0; i < 10; i++)
    {
        provider.TraceEvent();
    }

    for (int i = 0; i < 10; i++)
    {
        Sleep(1000);
    }

    dwRet = consumer.CloseTrace();
Exit0:
    controller.StopTrace();
    provider.UnregisterTrace();

    return 0;
}

