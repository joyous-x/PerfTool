#pragma once

#define KeyPercentThreshold L"percent"
#define KeyTimesThreshold   L"times"
#define KeyInterval         L"interval"
#define KeyProcNames        L"names"
#define Section_Normal   L"normal"
#define Section_Proc     L"process"

class KCfgLoader
{
public:
    DWORD Load(GLOBAL_CFG& cfg)
    {
        DWORD dwRet = -1;
        wchar_t wcsPath[MAX_PATH] = {0};
        if (0 ==  ::GetModuleFileName(NULL, wcsPath, MAX_PATH))
            goto Exit0;

        if (0 == ::PathRemoveFileSpec(wcsPath))
            goto Exit0;

        if (0 == ::PathAppend(wcsPath, L"kperftoolcfg.dat"))
            goto Exit0;

        dwRet = Load(wcsPath, cfg);
Exit0:
        return dwRet;
    }

    DWORD Load(const wchar_t* pcwcsCfgPath, GLOBAL_CFG& cfg)
    {
        DWORD dwRet = -1;
        if (0 == pcwcsCfgPath || 0 == ::PathFileExists(pcwcsCfgPath))
            goto Exit0;

        m_dwInterval = ::GetPrivateProfileInt(Section_Normal, KeyInterval, DefaultInterval, pcwcsCfgPath);
        m_dwPercentThreshold = ::GetPrivateProfileInt(Section_Normal, KeyPercentThreshold, DefaultPercentThreshold, pcwcsCfgPath);
        m_dwTimesThreshold = ::GetPrivateProfileInt(Section_Normal, KeyTimesThreshold, DefaultTimesThreshold, pcwcsCfgPath);

        DWORD dwSize = MAX_PATH; 
        wchar_t wcsTmp[MAX_PATH] = {0};
        ::GetPrivateProfileString(Section_Proc, KeyProcNames, DefaultProcNames, wcsTmp, dwSize, pcwcsCfgPath);

        m_vecProcNames.clear();
        Split(wcsTmp, L";", m_vecProcNames);

        cfg.dwInterval = m_dwInterval;
        cfg.dwPercentThreshold = m_dwPercentThreshold;
        cfg.dwTimesThreshold = m_dwTimesThreshold;
        cfg.dwProcNum = (DWORD)m_vecProcNames.size();
        cfg.wcsProcNames = m_vecProcNames;
Exit0:
        return dwRet;
    }

    DWORD Split(std::wstring str, std::wstring pattern, std::vector<std::wstring>& ret)
    {
        size_t pos = 0;
        str += pattern;

        for(size_t i = 0, size = str.size(); i < size; i++)
        {
            pos = str.find(pattern,i);
            std::wstring s=str.substr(i,pos-i);
            if (!s.empty()) ret.push_back(s);
            i= pos + pattern.size() - 1;
        }

        return 0;
    }
private:
    DWORD m_dwInterval;
    DWORD m_dwPercentThreshold;
    DWORD m_dwTimesThreshold;
    std::vector<std::wstring> m_vecProcNames;
};

