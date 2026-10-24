#include <Windows.h>

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
    IN     HANDLE    ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN     ULONG_PTR ZeroBits,
    IN OUT PSIZE_T   RegionSize,
    IN     ULONG     AllocationType,
    IN     ULONG     Protect
    );

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
    IN  HANDLE  ProcessHandle,
    IN  PVOID   BaseAddress,
    IN  PVOID   Buffer,
    IN  SIZE_T  NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );
