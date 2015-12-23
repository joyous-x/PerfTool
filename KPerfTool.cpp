// KPerfTool.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <vector>
#include <TlHelp32.h>
#include "GlobalFun.h"
#include "KPerfMOnitor.h"
#include "KCfgLoader.h"

GLOBAL_CFG g_cfg;

int _tmain(int argc, _TCHAR* argv[])
{
    g_cfg.default();

    KCfgLoader loader;
    loader.Load(g_cfg);

    KPerfMonitor monitor;
    monitor.Init();

	return 0;
}


