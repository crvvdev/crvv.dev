---
title: "EMACLAB Anticheat Driver, Part 4: Hooks"
last_modified_at: 2025-04-02T00:00:00-00:00
categories:
  - anticheat analysis
  - emaclab
  - gamersclub
  - driver
tags:
  - anticheat analysis
  - gamersclub
  - emaclab
  - driver
---

- File Name: EMAC-Driver-x64.sys
- TimeDateStamp: 0x67CAFFCE (Friday, 7 March 2025 14:16:46 GMT)
- Protector: VMProtect 3.8+

# Syscall hooks

Recently i have seen some people saying they where unable to read the game memory for some reason, and now you'll understand why that's a thing: they're intercepting syscalls.

### Infinityhook

A very long time ago Microsoft implemented something called PatchGuard (a.k.a KPP), that's a mechanism to protect the system integrity by actively verifying critical system structures and code. Today, it's not possible to directly hook system routines or modify the SSDT tables without triggering a BSOD, but some people found a way ~~(and pretty more ways)~~ to defeat PatchGuard or simply get around it. If your goal is simply to intercept system calls then everdox/infinityhook is your go to. But wait, wasn't infinityhook patched like 6 years ago? Yes it was, but it was quickly found a way to revive it, this repo: [wsnbbhehao/infinity-hook-pro_win7_win11](https://gitee.com/wsnbbhehao/infinity-hook-pro_win7_win11) for example, is a solution that works from Win7 up to latested Windows 11 version.

In all honesty i wasn't expecting such a thing from EMACLAB since there's no other anticheat (besides some controversial chinese anticheats) that actually uses infinityhook AFAIK.

_It's very easy to identify this as infinityhook due to the magic constants values..._
```cpp
char EmacGetCpuClock()
{
  int NtKiSystemCall64Offset; // edx
  void **v1; // rbx
  unsigned __int64 i; // rax
  int v3; // r9d
  int v4; // ecx
  __int64 v5; // rsi
  __int64 v6; // rdi
  unsigned __int64 *j; // rbx
  void *retaddr; // [rsp+28h] [rbp+0h] BYREF
  unsigned __int64 v10; // [rsp+30h] [rbp+8h] BYREF
  __int64 v11; // [rsp+38h] [rbp+10h] BYREF

  dword_FFFFF801BD006AFC = 1;
  NtKiSystemCall64Offset = FindNtKiSystemCall64Offset();
  dword_FFFFF801BD006AF8 = NtKiSystemCall64Offset;
  v1 = &retaddr;
  LOBYTE(i) = -(((unsigned __int64)IoGetStackLimits ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38);
  v11 = 0i64;
  v10 = 0i64;
  if ( !byte_FFFFF801BCFACDA0 && NtKiSystemCall64Offset != -1 )
  {
    v3 = *(_DWORD *)KeGetCurrentThread();
    for ( i = g_EmacInfinityHookList; i != g_EmacInfinityHookListEnd; i += 24i64 )
    {
      v4 = *(_DWORD *)(i + 4);
      if ( v4 != -1 && v4 == v3 ) 
      {
        v5 = *(_QWORD *)(i + 16);
        v6 = *(_QWORD *)(i + 8);
        if ( v5 )
        {
          LOBYTE(i) = ((__int64 (__fastcall *)(__int64 *, unsigned __int64 *))(((unsigned __int64)IoGetStackLimits ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoGetStackLimits ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))(
                        &v11,
                        &v10);
          if ( (unsigned __int64)&retaddr < v10 )
          {
            while ( 1 )
            {
              i = (unsigned __int64)(v1 + 1);
              if ( *(_WORD *)v1 == 0xF33 && (*(_DWORD *)i == 0x501802 || *(_DWORD *)i == 0x601802) )
                break;
              ++v1;
              if ( i >= v10 )
                return i;
            }
            for ( j = (unsigned __int64 *)(v1 + 2); (unsigned __int64)j < v10; ++j )
            {
              i = *j;
              if ( *j >= 0xEAADDEEAADDEADDEui64 && i < 0xAEADDEEADAEAADDEui64 )
              {
                i = (unsigned __int64)(j + 9);
                if ( (unsigned __int64)(j + 9) >= v10 )
                  return i;
                if ( *(_QWORD *)i == v5 && v6 )
                {
                  *(_QWORD *)i = v6;
                  return i;
                }
              }
            }
          }
        }
        return i;
      }
    }
  }
  return i;
}
```

---

Iterate throught syscall hook handlers lists, checks if syscall index and syscall routine matches, proceeds to _infinityhook_ the stack. If you're unfamiliar with this code i recommend taking a look at their respective repo's.

#### Handlers

Good, now we wan't to know which syscalls are being intercepted and what's actually being checked and done for each handler.

Here's the list of system routines intercepted and their respective actions:

__NtCreateThreadEx__ - Checks if process is game process, query StartRoutine and based on some factors proceed to verify if StartRoutine is __DbgBreakPoint__, __DbgUiRemoteBreakin__ or __DbgUserBreakPoint__. It will set a flag accordingly to each case/factor, which will be saved for report later.

__NtCreateThread__ - Same as _NtCreateThreadEx_.

__NtQueueApcThread__ - Checks if process is game process, query APC routine and based on some factors proceed to verify if APC routine is __DbgBreakPoint__, __DbgUiRemoteBreakin__, __DbgUserBreakPoint__, __LoadLibraryA__, __LoadLibraryW__, __LoadLibraryExA__, __LoadLibraryExW__ or __LdrLoadDll__, . It will set a flag accordingly to each case/factor, which will be saved for report later.

__NtQueueApcThreadEx__ - Same as _NtQueueApcThread_

__NtSetContextThread__ - Checks if process is game process, query Context->Rip and will set a flag accordingly to each case/factor, which will be saved for report later.

__NtAllocateVirtualMemory__ - This handler, based on some checks, will verify if calling process is `L"x86launcher.exe"` or `L"x64launcher.exe"`, if so it will let it proceed; if not will simply fail and create a report. This is most likely a fix for Steam launcher requiring a handle to game process.

__NtFreeVirtualMemory__ - This handler is probably used to fix edgy cases like Steam launcher requiring handle to game process and or other cases like csrss, no reports.

__NtProtectVirtualMemory__ - This handler is probably used to fix edgy cases like Steam launcher requiring handle to game process and or other cases like csrss, no reports.

__NtWriteVirtualMemory__ - Will generate a report if: current process is not Steam, csrss; target process is game.

__NtReadVirtualMemory__ - Will generate a report if any process that is not game process tries to read within game region size, as well as `engine2.dll` region size.

__NtMapViewOfSection__ - This handler is probably used to fix edgy cases like Steam launcher requiring handle to game process and or other cases like csrss, no reports.

__NtUnmapViewOfSection__ - This handler is probably used to fix edgy cases like Steam launcher requiring handle to game process and or other cases like csrss, no reports.

__NtUserFindWindowEx__ - Will generate a report if any process that is not Steam, game or EMAC white-listed processes query for window name `L"Counter-"`, lmao.

__NtUserSendInput__ - This handler will block any simulated input, from any process, and generate a report.

### Good sneakie

That's surely an extra layer of security, but in reality they had to infinityhook to fix some holes that Windows and Steam itself leaves in the system, because of HANDLE's.

The only downside is that all the handlers are calling a __virtualized__ function (sub_FFFFF801BCF4A358), i am not sure if that's appropriate when hooking system calls...

_the function called obtains the appropriate original procedure for the hook_
![img](/assets/img/emac-anticheat-driver-part4/callvm.png)

_uhh... i can see that's a vmenter_
![img](/assets/img/emac-anticheat-driver-part4/vmenter.png)

# It doesn't really ends here

There's another interesting aspect of the anticheat, i have discovered that they will also try to inline patch the system when some conditions are met.

```cpp
bool EmacCanHookSystem()
{
  int retLength; // [rsp+30h] [rbp+8h] BYREF
  __int64 v2; // [rsp+38h] [rbp+10h] BYREF

  v2 = 8i64;
  retLength = 0;
  return ((int (__fastcall *)(__int64, __int64 *, __int64, int *))((ZwQuerySystemInformation ^ qword_FFFFF801BCFACC40) & -(__int64)((ZwQuerySystemInformation ^ (unsigned __int64)qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))(
           103i64,                              // SystemCodeIntegrityInformation
           &v2,
           8i64,
           &retLength) < 0
      || (v2 & 0x140000000000i64) != 0;         // Check if test signing is enabled and if code integrity is disabled
}
```

They query system code integrity information, if system currently has test-signing on and nointegritychecks on it will install inline hooks in the following procedures:

- KeAttachProcess
- KeStackAttachProcess
- MmCopyVirtualMemory
- RtlFindExportedRoutineByName
- KeIsAttachedProcess
- MmGetSystemRoutineAddress

That's very confusing to me because i have tried running the anticheat at those conditions and i was unable to run the game, they keep telling me to disable test-signing and enable integrity checks...

For that reason i am unsure if getting into this subject is really necessary, i provide the .IDB so anyone curios can take a closer look.

But generally speaking those hooks will verify the return address, the most interesting part is that hooks in __RtlFindExportedRoutineByName__ and __MmGetSystemRoutineAddress__ will ensure that any newly loaded driver will end up calling their hooks for the respective functions they intercept in the first place, if that makes any sense.

# IDA decompiled snippets

[Hooks Snippets](https://github.com/crvvdev/emaclab-reversal/blob/main/hooks.c)

# Conclusion

Very interesting, that's the kind of stuff that's not really seen in other products.