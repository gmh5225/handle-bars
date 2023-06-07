#include "enumhandles.h"

int fetch_handles(unsigned short pid) {
    HMODULE h_ntdll;
    NTSTATUS status;
    ULONG retlen = 0;
    ULONG handleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo;

    h_ntdll = GetModuleHandleA("ntdll.dll");
    if (h_ntdll == NULL) {
        return -1;
    } 

    // Resolve NtQuerySystemInformation
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(
        h_ntdll, 
        "NtQuerySystemInformation"
    );

    if (NtQuerySystemInformation == NULL) {
        return -2;
    }

    handleInfo = (PSYSTEM_HANDLE_INFORMATION) malloc(handleInfoSize);
    if (handleInfo == NULL) {
        return -3;
    }

    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        &retlen
    )) == STATUS_INFO_LENGTH_MISMATCH) {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
        if (handleInfo == NULL)
            break; 
    }

    if (!NT_SUCCESS(status) || handleInfo == NULL)
    {
        printf("   [-] NtQuerySystemInformation failed!\n");     
        free(handleInfo);
        return -4;
    }

    for (int i = 0; i<handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO hInfo = handleInfo->Handles[i];
        if (hInfo.UniqueProcessId == pid) {
            printf("Handle 0x%x at 0x%p, PID: %d\n", hInfo.HandleValue, hInfo.Object, hInfo.UniqueProcessId);
            free(handleInfo);
            return 1;
        }
    }

    free(handleInfo);
    return 0;
}