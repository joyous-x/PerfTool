#pragma once

class KPathHelper
{
public:
    KPathHelper() : m_dwPid(0)
    {
        m_dwPid = ::GetCurrentProcessId();
        m_strInfo.Format(L"%d.%d.%d", g_cfg.dwPercentThreshold, g_cfg.dwTimesThreshold, m_dwPid);

        m_strDirPath = L"C:\\perf_dump";
        if (FALSE != ::PathFileExists(m_strDirPath))
        {
            return ;
        }

        ::CreateDirectory(m_strDirPath, NULL);
        if (FALSE == ::PathFileExists(m_strDirPath))
        {
            m_strDirPath = L"";
        }
    }

    std::wstring GetPath(const wchar_t* pcwcsSubName, BOOL bEnd)
    {
        if (m_strDirPath.IsEmpty()) return L"";

        DWORD dwIndex = 0;
        if (NULL == pcwcsSubName) return NULL;

        if (bEnd && m_dwIndex.size() > 0 && m_dwIndex.end() == m_dwIndex.find(pcwcsSubName)) 
        {
            return NULL;
        }
        
        if (FALSE == bEnd)
        {
            m_dwIndex[pcwcsSubName]++;
        }

        dwIndex = m_dwIndex[pcwcsSubName];

        CString strPath;
        strPath.Format(L"%s\\%s_%s_%d.%s.dmp", m_strDirPath, pcwcsSubName, m_strInfo, dwIndex, (bEnd ? L"end" : L"start"));
        return strPath.GetBuffer();
    }
private:
    std::map<std::wstring, DWORD> m_dwIndex;
    CString m_strDirPath;
    CString m_strInfo;
    DWORD   m_dwPid;
};