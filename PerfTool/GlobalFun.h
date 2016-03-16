#pragma once
#include "stdafx.h"

class CGlobalFun
{
private:
    CGlobalFun(void)
    {    }

public:
    static BOOL AddPrivilege(const CString& strPrivilege);
    static DWORD GetNumberofProcessors();

    static BOOL IsWin8System();
    static BOOL IsVistaSystem();
    static BOOL IsWin7System();
    static BOOL IsWin2000System();
    static BOOL GetProcessFullPath(HANDLE hProcess, LPWSTR lpszFullPath);
private:
    static BOOL _ConvertDevicePath(LPWSTR lpszFullPath);
};
