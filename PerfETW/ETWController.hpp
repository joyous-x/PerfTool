#include "stdafx.h"

// Include this #define to use SystemTraceControlGuid in Evntrace.h.
#define INITGUID

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <evntrace.h>

class ETWController 
{
public:
    ETWController(const GUID& Provider) : m_bInited(FALSE), m_pSessionProperties(NULL), m_hSessionHandle(0), m_ProviderGuid(Provider)
    {   }

    DWORD StartTrace()
    {
        ULONG uRet = ERROR_SUCCESS;
        if (m_bInited)
        {
            goto cleanup;
        }

        if (NULL == m_pSessionProperties)
        {
            m_pSessionProperties = MakeSessionProperties();
        }

        if (NULL == m_pSessionProperties)
        {
            goto cleanup;
        }

        uRet = ::StartTrace((PTRACEHANDLE)&m_hSessionHandle, SESSION_NAME, m_pSessionProperties);
        if (uRet != ERROR_SUCCESS)
        {
            goto cleanup;
        }

        if (0 == m_hSessionHandle)
        {
            goto cleanup;
        }

        m_bInited = TRUE;
cleanup:
        if (FALSE == m_bInited)
        {
            this->StopTrace();
        }
        return uRet;
    }

    DWORD StopTrace()
    {
        ULONG uRet = ERROR_SUCCESS;
        m_bInited = FALSE;

        if (NULL == m_pSessionProperties)
        {
            EVENT_TRACE_PROPERTIES* pSessionProperties = MakeSessionProperties();
            uRet = StopTrace(m_hSessionHandle, pSessionProperties);
        }
        else
        {
            uRet = StopTrace(m_hSessionHandle, m_pSessionProperties);
        }

        return uRet;
    }

    DWORD EnableTrace(ULONG EnableFlag, ULONG EnableLevel)
    {
        ULONG uRet = ::EnableTrace(TRUE, EnableFlag, EnableLevel, (LPGUID)&m_ProviderGuid, m_hSessionHandle);
        return uRet;
    }

private:
    DWORD StopTrace(TRACEHANDLE& hSessionHandle, EVENT_TRACE_PROPERTIES* &pSessionProperties)
    {
        ULONG uRet = ERROR_SUCCESS;

        if (hSessionHandle)
        {
            uRet = ::ControlTrace(hSessionHandle, 0, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
            hSessionHandle = 0;
        }
        else
        {
            uRet = ::ControlTrace(NULL, SESSION_NAME, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
        }

        if (pSessionProperties)
        {
            free(pSessionProperties);
            pSessionProperties = NULL;
        }

        return uRet;
    }

    EVENT_TRACE_PROPERTIES* MakeSessionProperties() 
    {
        ULONG uBufferSize = 0;
        EVENT_TRACE_PROPERTIES* pSessionProperties = 0;

        uBufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SESSION_NAME);
        pSessionProperties = (EVENT_TRACE_PROPERTIES*) malloc(uBufferSize);
        if (NULL == pSessionProperties)
        {
            return NULL;
        }

        ZeroMemory(pSessionProperties, uBufferSize);
        pSessionProperties->Wnode.BufferSize = uBufferSize;
        pSessionProperties->Wnode.Guid = m_ProviderGuid; // session guid
        pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pSessionProperties->Wnode.ClientContext = 1;
        pSessionProperties->EnableFlags = SESSION_ENABLE_FLAGS;
        pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        return pSessionProperties;
    }

private:
    BOOL        m_bInited;
    GUID        m_ProviderGuid;
    TRACEHANDLE m_hSessionHandle;
    EVENT_TRACE_PROPERTIES* m_pSessionProperties;
};