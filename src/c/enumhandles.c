#include <stdarg.h>
#include "enumhandles.h"

_NtQuerySystemInformation NtQuerySystemInformation;
_NtDuplicateObject NtDuplicateObject;
_NtQueryObject NtQueryObject;
_RtlInitUnicodeString RtlInitUnicodeString;
_RtlEqualUnicodeString RtlEqualUnicodeString;

void _dprintf(const char *format, ...)
{
#ifdef DEBUG
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsprintf(buffer, format, args);
    printf(buffer);
    va_end(args);
#endif
}

void _deprintf(const char *format, ...)
{
#ifdef DEBUG
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsprintf(buffer, format, args);
    fprintf(stderr, buffer);
    va_end(args);
#endif
}

PVOID get_lib_proc_addr(PSTR lib_name, PSTR proc_name)
{
    _dprintf("[i] Resolving Address:\t %s(%s)\n", proc_name, lib_name);
    HMODULE hModule = GetModuleHandleA(lib_name);

    if (hModule == NULL)
    {
        _deprintf("[i] Got Handle to:\t%s\n", lib_name);
        return NULL;
    }

    PVOID addr = (PVOID)GetProcAddress(hModule, proc_name);
    if (addr == NULL)
    {
        _deprintf("[!] Failed to resolve:\t %s\n", proc_name);
        return NULL;
    }
    _dprintf("[i] Resolved Function:\t %s(0x%p)\n", proc_name, addr);
    return addr;
}

int resolve_functions() {
    NtQuerySystemInformation = get_lib_proc_addr("ntdll.dll", "NtQuerySystemInformation");
    NtDuplicateObject = get_lib_proc_addr("ntdll.dll", "NtDuplicateObject");
    NtQueryObject = get_lib_proc_addr("ntdll.dll", "NtQueryObject");
    RtlInitUnicodeString = get_lib_proc_addr("ntdll.dll", "RtlInitUnicodeString");
    RtlEqualUnicodeString = get_lib_proc_addr("ntdll.dll", "RtlEqualUnicodeString");
    if (RtlInitUnicodeString == NULL || RtlEqualUnicodeString == NULL || NtQuerySystemInformation == NULL || NtDuplicateObject == NULL || NtQueryObject == NULL) {
        return -1;
    }

    return 0;
}

const char *permission_from_dword(ACCESS_MASK GrantedAccess)
{
    switch (GrantedAccess)
    {
    case PROCESS_ALL_ACCESS:
        return "PROCESS_ALL_ACCESS";
    case PROCESS_CREATE_PROCESS:
        return "PROCESS_CREATE_PROCESS";
    case PROCESS_CREATE_THREAD:
        return "PROCESS_CREATE_THREAD";
    case PROCESS_DUP_HANDLE:
        return "PROCESS_DUP_HANDLE";
    case PROCESS_QUERY_INFORMATION:
        return "PROCESS_QUERY_INFORMATION";
    case PROCESS_QUERY_LIMITED_INFORMATION:
        return "PROCESS_QUERY_LIMITED_INFORMATION";
    case PROCESS_SET_INFORMATION:
        return "PROCESS_SET_INFORMATION";
    case PROCESS_SET_QUOTA:
        return "PROCESS_SET_QUOTA";
    case PROCESS_SUSPEND_RESUME:
        return "PROCESS_SUSPEND_RESUME";
    case PROCESS_TERMINATE:
        "PROCESS_TERMINATE ";
    case PROCESS_VM_OPERATION:
        return "PROCESS_VM_OPERATION";
    case PROCESS_VM_READ:
        return "PROCESS_VM_READ";
    case PROCESS_VM_WRITE:
        return "PROCESS_VM_WRITE";
    case SYNCHRONIZE:
        return "SYNCHRONIZE";
    default:
        return "Other";
    };
}

int fetch_handles(DWORD pid) {
    HANDLE hProcess;
    NTSTATUS status;
    ULONG handleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION hInfo;
    UNICODE_STRING pProcess, pThread, pFile, pKey;
    // Resolve Function Names
    if (resolve_functions() != 0) {
        _deprintf("[!] Failed to resolve Nt functions\n");
        return -1;
    }


    RtlInitUnicodeString(&pKey, L"Key");
    RtlInitUnicodeString(&pFile, L"File");
    RtlInitUnicodeString(&pThread, L"Thread");
    RtlInitUnicodeString(&pProcess, L"Process");

    // Open Handle to Process ID
    hProcess = OpenProcess(
        PROCESS_DUP_HANDLE,     // Required to duplicate a handle
        FALSE,                  // Do not inherit handle
        pid);                   // Process ID 

    if (hProcess == NULL) {
        fprintf(stderr, "[!] OpenProcess() Failed! (0x%x)", GetLastError());
        return -1;
    }

    hInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
    if (hInfo == NULL) {
        fprintf(stderr, "[!] malloc() Failed! (0x%x)", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    // NtQuerySystemInformation won't give us the correct buffer size,
    // so we guess by doubling the buffer size.
    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
    while (1) {
        // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm
        status = NtQuerySystemInformation(
            SystemHandleInformation,
            hInfo,
            handleInfoSize,
            NULL);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            hInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(hInfo, handleInfoSize *= 2);
            if (hInfo == NULL) {
                fprintf(stderr, "[!] realloc() Failed! (0x%x)", GetLastError());
                CloseHandle(hProcess);
                return -1;
            }
        }
        // NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
        else if (!NT_SUCCESS(status)) {
            fprintf(stderr, "[!] NtQuerySystemInformation() failed (0x%x)\n", status);
            free(hInfo);
            CloseHandle(hProcess);
            return -1;
        }
        else {
            break;
        }
    }

    _dprintf("[i] Total umber of handles found: %d", hInfo->HandleCount);

    for (int i = 0; i < hInfo->HandleCount; i++) {
        ULONG returnLength;
        PVOID objectNameInfo;
        HANDLE dupHandle = NULL;
        UNICODE_STRING objectName;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        SYSTEM_HANDLE handle = hInfo->Handles[i];

        // Check if this handle belongs to the PID the user specified.
        if (handle.ProcessId != pid)
            continue;

        _dprintf("\n[i] 0x%08x | 0x%p | %s",
                handle.Handle,
                handle.Object,
                permission_from_dword(handle.GrantedAccess));

        // https://github.com/tamentis/psutil/blob/7c1f4d1fe2fd523c23e25b2e8b4344158e9fdff7/psutil/arch/mswindows/process_handles.c#L178
        if((handle.GrantedAccess == 0x0012019f)
        || (handle.GrantedAccess == 0x001a019f)
        || (handle.GrantedAccess == 0x00120189)
        || (handle.GrantedAccess == 0x00100000)) {
            _dprintf(" (Unwanted Access Right)");
            continue;
        }

        // Duplicate the handle so we can query it.
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject
        status = NtDuplicateObject(
            hProcess,
            (void *)handle.Handle,
            GetCurrentProcess(),
            &dupHandle,
            0,
            0,
            0);

        if (!NT_SUCCESS(status)) {
            _deprintf(" (Duplication Failed)");
            CloseHandle(dupHandle);
            continue;
        }

        // Query Object type
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (objectTypeInfo == NULL) {
            fprintf(stderr, "\n[!] Malloc() failed for OBJECT_TYPE_INFORMATION (0x%x)\n", GetLastError());
            free(hInfo);
            CloseHandle(dupHandle);
            CloseHandle(hProcess);
            return -1;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
        status = NtQueryObject(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            _deprintf(" (Object Type Query Failed)");
            CloseHandle(dupHandle);
            free(objectTypeInfo);
            continue;
        }

        // Query the object name (unless it has an access of 0x0012019f, on which NtQueryObject could hang.
        objectNameInfo = malloc(0x1000);
        if (objectNameInfo == NULL) {
            fprintf(stderr, "\n[!] Malloc() failed for objectNameInfo (0x%x)\n", GetLastError());
            free(hInfo);
            free(objectTypeInfo);

            CloseHandle(dupHandle);
            CloseHandle(hProcess);
            return -1;
        }

        status = NtQueryObject(
            dupHandle,
            ObjectNameInformation,
            objectNameInfo,
            0x1000,
            &returnLength
        );

        if (!NT_SUCCESS(status)) {
            // Reallocate the buffer and try again.
            objectNameInfo = realloc(objectNameInfo, returnLength); 
            if (objectNameInfo == NULL) {
                fprintf(stderr, "\n[!] Realloc() failed for objectNameInfo (0x%x)\n", GetLastError());
                free(hInfo);
                free(objectTypeInfo);
                free(objectNameInfo);

                CloseHandle(dupHandle);
                CloseHandle(hProcess);
                return -1;
            }

            status = NtQueryObject(
                dupHandle,
                ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
            );

            if (!NT_SUCCESS(status)) {
                _deprintf(" (Object Name Query Failed)");
                free(objectTypeInfo);
                free(objectNameInfo);

                CloseHandle(dupHandle);
                continue;
            }
        }

        // Cast our buffer into an UNICODE_STRING.
        objectName = *(PUNICODE_STRING)objectNameInfo;

        // Print the information!
        if (objectName.Length) {
            // The object has a name.
            _dprintf(
                " (%.*S: %.*S)",
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer,
                objectName.Length / 2,
                objectName.Buffer
            );
        }
        else {
            // Print something else.
            _dprintf(
                " (%.*S: [unnamed])",
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer);
        }

        // Operations with Handles
        if (RtlEqualUnicodeString(&objectTypeInfo->Name, &pProcess, TRUE)) {
            // Do Something with a Process Handle
        }
        else if (RtlEqualUnicodeString(&objectTypeInfo->Name, &pThread, TRUE) ) {
            // Do something with a thread handle
            // HANDLE hThread = (HANDLE)handle.Handle;
        }
        else if (RtlEqualUnicodeString(&objectTypeInfo->Name, &pFile, TRUE) ) {
            // Do something with file handle
            printf("[i] Filename: %.*S (0x%x)\n", objectName.Length / 2, objectName.Buffer, handle.Handle);
            const int MAX_LENGTH = 10;
            char buffer[1000];
            DWORD bytesRead;
           
           HANDLE hFileMapping = CreateFileMappingA(
                   (HANDLE)handle.Handle,
                    NULL,
                    PAGE_READONLY,
                    0,
                    0,
                    NULL
                );
            if (hFileMapping==NULL) {
                printf("Oops\n");
            }
            CloseHandle(hFileMapping);

        }

        else if (RtlEqualUnicodeString(&objectTypeInfo->Name, &pKey, TRUE) ) {
            // Do Something with registry key
        }
        else {
            continue;
        }

        free(objectNameInfo);
        free(objectTypeInfo);
        CloseHandle(dupHandle);
    }

    free(hInfo);
    CloseHandle(hProcess);
    return 0;
}