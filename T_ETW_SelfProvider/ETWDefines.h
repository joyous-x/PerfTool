#pragma once
#include <Windows.h>

// GUID that identifies the provider that you are registering.
// The GUID is also used in the provider MOF class. 
// Remember to change this GUID if you copy and paste this example.

// {7C214FB1-9CAC-4b8d-BAED-7BF48BF63BB3}
static const GUID ProviderGuid = 
{ 0x7c214fb1, 0x9cac, 0x4b8d, { 0xba, 0xed, 0x7b, 0xf4, 0x8b, 0xf6, 0x3b, 0xb3 } };

// GUID that identifies the category of events that the provider can log. 
// The GUID is also used in the event MOF class. 
// Remember to change this GUID if you copy and paste this example.

// Event trace class GUID.
// {B49D5931-AD85-4070-B1B1-3F81F1532875}
static const GUID CategoryGuid_Test = 
{ 0xb49d5931, 0xad85, 0x4070, { 0xb1, 0xb1, 0x3f, 0x81, 0xf1, 0x53, 0x28, 0x75 } };


// Identifies the event type within the MyCategoryGuid category 
// of events to be logged. This is the same value as the EventType 
// qualifier that is defined in the event type MOF class for one of 
// the MyCategoryGuid category of events.
// If you define your own event types, you should use numbers starting from 10
#define EVENT_TYPE_TEST         (11)

#define EVENT_VERSION_TEST      (1)


#define LOGFILE_PATH    L"D:\\Log.etl"
#define SESSION_NAME    L"test"


// GUID used as the value for EVENT_DATA.ID.
static const GUID dataID = 
{ 0x25baeda9, 0xc81a, 0x4889, { 0x87, 0x64, 0x18, 0x4f, 0xe5, 0x67, 0x50, 0xf2 } };

// Application data to be traced for Version 1 of the MOF class.
typedef struct _evt_data
{
    LONG    Cost;
    DWORD   Indices[3];
    WCHAR   Signature[32];
    BOOL    IsComplete;
    GUID    ID;
    DWORD   Size;
}EVENT_DATA, *PEVENT_DATA;