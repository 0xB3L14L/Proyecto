#include <windows.h>
#include "tcg.h"

__declspec(dllimport) VOID    WINAPI KERNEL32$Sleep(DWORD);
__declspec(dllimport) int     WINAPI USER32$MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT);

void go() {
    KERNEL32$Sleep(3000);
    
    USER32$MessageBoxW(NULL, L"Module Stomp, Carokann funcionan", L"Prueba",
                       MB_OK | MB_ICONINFORMATION | 0x00040000);
}