#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <wmistr.h>
#include <evntrace.h>

TRACE_GUID_REGISTRATION g_EventClassGuids[] = {
    (LPGUID)&CategoryGuid_Test, NULL
};

// Event passed to TraceEvent
typedef struct _trace_event_data
{
    EVENT_TRACE_HEADER  Header;
    MOF_FIELD           Data[MAX_MOF_FIELDS];  // Event-specific data
} TRACE_EVENT_DATA, *PTRACE_EVENT_DATA;


ULONG WINAPI Callback(WMIDPREQUESTCODE RequestCode,PVOID Context,ULONG* Reserved,PVOID Header);


// Before calling TraceEvent, we need enable the provider first.
class ETWProvider
{
public:
    ETWProvider() : m_RegistrationHandle(0), m_bInited(FALSE), m_bTraceOn(FALSE),
        m_SessionHandle(0), m_uEnableFlags(0), m_uEnableLevel(0)
    { }

    DWORD UnregisterTrace()
    {
        ULONG uRet = ERROR_SUCCESS;
        if (m_RegistrationHandle)
        {
            uRet = ::UnregisterTraceGuids(m_RegistrationHandle);
            m_RegistrationHandle = 0;
        }

        m_bInited = FALSE;
        return uRet;
    }

    DWORD RegisterTrace()
    {
        ULONG uRet = ERROR_SUCCESS;
        if (m_bInited)
        {
            goto Exit0;
        }

        // Register the provider and specify the control callback function
        // that receives the enable/disable notifications.

        uRet = ::RegisterTraceGuids(
            (WMIDPREQUEST)Callback,
            this,
            (LPGUID)&ProviderGuid,
            sizeof(g_EventClassGuids)/sizeof(TRACE_GUID_REGISTRATION),
            g_EventClassGuids,
            NULL,
            NULL,
            &m_RegistrationHandle
            );
        if (ERROR_SUCCESS != uRet)
        {
            goto Exit0;
        }

        m_bInited = TRUE;
Exit0:
        return uRet;
    }

    DWORD TraceEvent()
    {
        ULONG uRet = ERROR_SUCCESS;

        // Set the event-specific data.
        EVENT_DATA data;
        data.Cost = 32;
        data.ID = dataID;
        data.Indices[0] = 4;
        data.Indices[1] = 5;
        data.Indices[2] = 6;
        data.IsComplete = TRUE;
        wcscpy_s(data.Signature, 32, L"joyoushunter");
        data.Size = 1024;

        TRACE_EVENT_DATA event;
        ZeroMemory(&event, sizeof(event));
        event.Header.Size = sizeof(EVENT_TRACE_HEADER) + (sizeof(MOF_FIELD) * 6);
        event.Header.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_USE_MOF_PTR;
        event.Header.Guid = CategoryGuid_Test;
        event.Header.Class.Type = EVENT_TYPE_TEST;
        event.Header.Class.Version = EVENT_VERSION_TEST;
        event.Header.Class.Level = m_uEnableLevel;

        // Load the event data.
        DEFINE_TRACE_MOF_FIELD(&event.Data[0], &data.Cost, sizeof(data.Cost), 0);
        DEFINE_TRACE_MOF_FIELD(&event.Data[1], &data.Indices[0], sizeof(data.Indices), 0);
        DEFINE_TRACE_MOF_FIELD(&event.Data[2], &data.Signature[0], sizeof(data.Signature), 0);
        DEFINE_TRACE_MOF_FIELD(&event.Data[3], &data.IsComplete, sizeof(data.IsComplete), 0);
        DEFINE_TRACE_MOF_FIELD(&event.Data[4], &data.ID, sizeof(data.ID), 0);
        DEFINE_TRACE_MOF_FIELD(&event.Data[5], &data.Size, sizeof(data.Size), 0);

        if (FALSE == m_bTraceOn || (0 != m_uEnableLevel && TRACE_LEVEL_ERROR > m_uEnableLevel))
        {
            return ERROR_INVALID_PARAMETER;
        }

        uRet = ::TraceEvent(m_SessionHandle, &(event.Header));
        if (ERROR_SUCCESS != uRet)
        {
            DWORD dwError = ::GetLastError();
            m_bTraceOn = FALSE;
        }

        return uRet;
    }

    // The callback function that receives enable/disable notifications
    // from one or more ETW sessions. Because more than one session
    // can enable the provider, this example ignores requests from other 
    // sessions if it is already enabled.
    DWORD ControlCallback(
        WMIDPREQUESTCODE RequestCode,
        PVOID            Context,
        ULONG*           Reserved,
        PVOID            Header)
    {
        Context, Reserved;

        ULONG status = ERROR_SUCCESS;
        TRACEHANDLE TempSessionHandle = 0; 

        switch (RequestCode)
        {
        case WMI_ENABLE_EVENTS:
            {
                ::SetLastError(0);

                // If the provider is already enabled to a provider, ignore the request.
                // Get the session handle of the enabling session. You need the session 
                // handle to call the TraceEvent function. The session could be enabling 
                // the provider or it could be updating the level and enable flags.

                TempSessionHandle = ::GetTraceLoggerHandle(Header);
                if (INVALID_HANDLE_VALUE == (HANDLE)TempSessionHandle)
                {
                    break;
                }

                if (0 == m_SessionHandle)
                {
                    m_SessionHandle = TempSessionHandle;
                }
                else if (m_SessionHandle != TempSessionHandle)
                {
                    break;
                }

                // Get the severity level of the events that the session wants you to log.

                m_uEnableLevel = ::GetTraceEnableLevel(m_SessionHandle); 
                if (0 == m_uEnableLevel)
                {
                    // If zero, determine whether the session passed zero or an error occurred.

                    if (ERROR_SUCCESS == (status = GetLastError()))
                    {
                        // Decide what a zero enable level means to your provider.
                        // For this example, it means log all events.
                    }
                    else
                    {
                        break;
                    } 
                }

                // Get the enable flags that indicate the events that the
                // session wants you to log. The provider determines the
                // flags values. How it articulates the flag values and 
                // meanings to perspective sessions is up to it.

                m_uEnableFlags = ::GetTraceEnableFlags(m_SessionHandle);
                if (0 == m_uEnableFlags)
                {
                    // If zero, determine whether the session passed zero or an error occurred.

                    if (ERROR_SUCCESS == (status = GetLastError()))
                    {
                        // Decide what a zero enable flags value means to your provider.
                    }
                    else
                    {
                        break;
                    }
                }

                m_bTraceOn = TRUE;
                break;
            }
        case WMI_DISABLE_EVENTS:
            {
                // Disable the provider only if the request is coming from the
                // session that enabled the provider.

                TempSessionHandle = ::GetTraceLoggerHandle(Header);
                if (INVALID_HANDLE_VALUE == (HANDLE)TempSessionHandle)
                {
                    break;
                }

                if (m_SessionHandle == TempSessionHandle)
                {
                    m_bTraceOn = FALSE;
                    m_SessionHandle = 0;
                }
                break;
            }
        default:
            {
                status = ERROR_INVALID_PARAMETER;
                break;
            }
        }

        return status;
    }

    TRACEHANDLE GetSessionHandle()
    {
        return m_SessionHandle;
    }

private:
    BOOL            m_bInited;
    BOOL            m_bTraceOn;
    TRACEHANDLE     m_SessionHandle;     // The handle to the session that enabled the provider.
    ULONG           m_uEnableFlags;      // Determines which class of events to log.
    UCHAR           m_uEnableLevel;      // Determines the severity of events to log.
    TRACEHANDLE     m_RegistrationHandle;
};

ULONG WINAPI Callback(WMIDPREQUESTCODE RequestCode,PVOID Context,ULONG* Reserved,PVOID Header)
{
    DWORD uRet = ERROR_INVALID_PARAMETER;
    if (NULL == Context)
    {
        return uRet;
    }

    ETWProvider* provider = (ETWProvider*)Context;
    uRet = provider->ControlCallback(RequestCode, NULL, Reserved, Header);
    return uRet;
}

