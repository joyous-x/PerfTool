// KPerfTool.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <vector>
#include <TlHelp32.h>
#include "GlobalFun.h"
#include "KPerfMOnitor.h"
#include "KCfgLoader.h"


int _tmain(int argc, _TCHAR* argv[])
{
    KCfgLoader loader;
    loader.Load(g_cfg);

    KPerfMonitor monitor;
    monitor.Init();

	return 0;
}


