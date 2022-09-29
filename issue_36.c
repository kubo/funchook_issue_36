#include <stdio.h>
#include <assert.h>
#include <windows.h>
#include "funchook.h"

typedef LPWSTR (*GetCommandLineW_func_t)(void);

static GetCommandLineW_func_t trampoline_func;

static LPWSTR hook_func(void)
{
    return trampoline_func();
}

int main()
{
    funchook_t *funchook = funchook_create();
    HMODULE hMod = GetModuleHandleA("kernelbase.dll");
    GetCommandLineW_func_t target_func = (GetCommandLineW_func_t)GetProcAddress(hMod, "GetCommandLineW");
    const wchar_t *original_cmdline = GetCommandLineW();
    int rv;

    assert(memcmp(target_func, "\x48\x8b\x05", 3) == 0);
    size_t original_read_addr = (size_t)target_func + 7 + *(int*)((size_t)target_func + 3);

    trampoline_func = target_func;
    rv = funchook_prepare(funchook, (void**)&trampoline_func, hook_func);
    assert(rv == 0);

    assert(trampoline_func != target_func);
    assert(memcmp(trampoline_func, "\x48\x8b\x05", 3) == 0);
    size_t trampoline_read_addr = (size_t)trampoline_func + 7 + *(int*)((size_t)trampoline_func + 3);

    printf("original func: func_addr=%p, offset=%d, read_addr=%p\n",
           (void*)target_func, *(int*)((size_t)target_func + 3), (void*)original_read_addr);
    printf("trampoline func: func_addr=%p, offset=%d, read_addr=%p\n",
           (void*)trampoline_func, *(int*)((size_t)trampoline_func + 3), (void*)trampoline_read_addr);
    assert(original_read_addr == trampoline_read_addr);

    rv = funchook_install(funchook, 0);
    assert(rv == 0);
    assert(original_cmdline == trampoline_func());
    assert(original_cmdline == target_func());
    rv = funchook_uninstall(funchook, 0);
    assert(rv == 0);

    printf("ok\n");
    return 0;
}
