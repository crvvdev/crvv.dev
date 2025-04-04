---
title: "EMACLAB Anticheat Driver, Part 6: Integrity checks"
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

# Integrity checks

To bypass kernel anticheats, cheaters can simply load their own driver, or even better, manual map it into system memory and try hide itself as much as possible and once the driver is mapped and hidden in memory anticheats have to find it. The anticheat kernel driver itself will not help if there are no integrity checks being actively made on the system, it's important that anticheats actively scans for traces as well as use patterns and heuristics for detections.

## How anticheats find unsigned code

Threads: Any code that actually runs in memory is attached to a thread, there are several threads running on the computer. You can iterate the system threads list and obtain thread stack back trace.

- NMI - It's possible to register non-maskable interrupts (NMIs) and obtain thread stack back trace.
- APC - It's possible to send APC to thread and obtain information, or, simply dump it directly.

The stack back trace contains all the informations necessary to find unsigned code being run, that's great because scanning memory can be tricky and very error prone.

### Kernel stack back trace

Sadly the NMI callback is virtualized, but it's possible to sneak the code which iterate system threads and obtains its informations:

_huge EasyAntiCheat thread stack trace code vibes here_
```cpp
void __fastcall EmacGetThreadStartAddressWorkItem(__int64 a1, _EMAC_WORK_ITEM_CONTEXT *context)
{
  void (__fastcall *KeSetEventFn)(PKEVENT, _QWORD, _QWORD); // rbp
  PIO_WORKITEM WorkItem; // rax
  _WORK_QUEUE_ITEM *Flink; // rdi
  _EMAC_WORK_ITEM_CONTEXT *Parameter; // rsi
  PIO_WORKITEM v7; // rcx
  void *ThreadWin32StartAddress; // rax

  if ( context )
  {
    KeSetEventFn = (void (__fastcall *)(PKEVENT, _QWORD, _QWORD))(((unsigned __int64)KeSetEvent ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)KeSetEvent ^ qword_FFFFF801BCFACC40)));
    WorkItem = context->WorkItem;
    if ( WorkItem )
    {
      if ( context->Thread )
      {
        Flink = *(_WORK_QUEUE_ITEM **)WorkItem;
        if ( *(_QWORD *)WorkItem )
        {
          if ( Flink == (_WORK_QUEUE_ITEM *)WorkItem )
          {
            while ( Flink != (_WORK_QUEUE_ITEM *)context->WorkItem )
            {
              Parameter = (_EMAC_WORK_ITEM_CONTEXT *)Flink->Parameter;
              if ( IsWindows10() && *(PVOID *)&Parameter[1].Event.Header.Lock == context->Thread
                || (v7 = Parameter->WorkItem) != 0i64 && !EmacGetModuleInfoFromAddress((unsigned __int64)v7, 1) )
              {
                context->Unknown2 = Parameter->WorkItem;
                break;
              }
              Flink = (_WORK_QUEUE_ITEM *)Flink->List.Flink;
              if ( !Flink )
                break;
            }
          }
        }
      }
    }
    ThreadWin32StartAddress = (void *)EmacGetThreadWin32StartAddress(KeGetCurrentThread());
    context->ThreadStartAddress = ThreadWin32StartAddress;
    if ( !EmacIsAddressInCodeSectionRange(
            (unsigned __int64)ThreadWin32StartAddress,
            (_IMAGE_DOS_HEADER *)g_NtoskrnlBase,
            0i64) )
      context->ThreadStartAddress = 0i64;
    KeSetEventFn(&context->Event, 0i64, 0i64);
  }
}

char __fastcall EmacGetThreadStartAddress(PETHREAD Thread, void **a2, void **StartAddress)
{
  char v3; // bl
  void (__fastcall *KeInitializeEventFn)(PKEVENT, _QWORD, _QWORD); // r13
  void (__fastcall *IoQueueWorkItemFn)(struct _IO_WORKITEM *, void (__fastcall *)(__int64, _EMAC_WORK_ITEM_CONTEXT *), __int64, _EMAC_WORK_ITEM_CONTEXT *); // r15
  void (__fastcall *KeWaitForSingleObjectFn)(void *, _QWORD, _QWORD, _QWORD, _QWORD); // r12
  __int64 (__fastcall *ExAllocatePoolWithTagFn)(_QWORD, __int64, _QWORD); // r9
  void (__fastcall *ExFreePoolWithTagFn)(_EMAC_WORK_ITEM_CONTEXT *, _QWORD); // rbp
  _EMAC_WORK_ITEM_CONTEXT *Context; // rax MAPDST
  struct _IO_WORKITEM *workItem; // rax
  __int64 (__fastcall *IoAllocateWorkItemFn)(__int64); // [rsp+78h] [rbp+10h]

  v3 = 0;
  KeInitializeEventFn = (void (__fastcall *)(PKEVENT, _QWORD, _QWORD))(((unsigned __int64)KeInitializeEvent ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeInitializeEvent ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  IoAllocateWorkItemFn = (__int64 (__fastcall *)(__int64))(((unsigned __int64)IoAllocateWorkItem ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoAllocateWorkItem ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  IoQueueWorkItemFn = (void (__fastcall *)(struct _IO_WORKITEM *, void (__fastcall *)(__int64, _EMAC_WORK_ITEM_CONTEXT *), __int64, _EMAC_WORK_ITEM_CONTEXT *))(((unsigned __int64)IoQueueWorkItem ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)IoQueueWorkItem ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  KeWaitForSingleObjectFn = (void (__fastcall *)(void *, _QWORD, _QWORD, _QWORD, _QWORD))(((unsigned __int64)KeWaitForSingleObject ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)KeWaitForSingleObject ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  ExAllocatePoolWithTagFn = (__int64 (__fastcall *)(_QWORD, __int64, _QWORD))(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  ExFreePoolWithTagFn = (void (__fastcall *)(_EMAC_WORK_ITEM_CONTEXT *, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  if ( a2 )
    *a2 = 0i64;
  if ( StartAddress )
    *StartAddress = 0i64;
  Context = (_EMAC_WORK_ITEM_CONTEXT *)ExAllocatePoolWithTagFn(0i64, 0x38i64, 'CAME');
  if ( Context )
  {
    *(_OWORD *)&Context->Event.Header.Lock = 0i64;
    *(_OWORD *)&Context->Event.Header.WaitListHead.Blink = 0i64;
    *(_OWORD *)&Context->WorkItem = 0i64;
    Context->ThreadStartAddress = 0i64;
    KeInitializeEventFn(&Context->Event, 0i64, 0i64);
    Context->Thread = Thread;
    Context->ThreadStartAddress = 0i64;
    Context->Unknown2 = 0i64;
    workItem = (struct _IO_WORKITEM *)IoAllocateWorkItemFn(g_EmacDeviceObject);
    Context->WorkItem = workItem;
    if ( workItem )
    {
      IoQueueWorkItemFn(workItem, EmacGetThreadStartAddressWorkItem, 1i64, Context);
      KeWaitForSingleObjectFn(Context, 0i64, 0i64, 0i64, 0i64);
      if ( a2 )
        *a2 = Context->Unknown2;
      if ( StartAddress )
        *StartAddress = Context->ThreadStartAddress;
      if ( Context->Unknown2 || Context->ThreadStartAddress )
        v3 = 1;
    }
    ExFreePoolWithTagFn(Context, 'CAME');
    LOBYTE(Context) = v3;
  }
  return (char)Context;
}

ULONG_PTR *__fastcall EmacVerifyKernelThreadsStackTrace(unsigned __int64 a1, void *a2, unsigned int a3, ULONG64 a4)
{
  ULONG64 v4; // r12
  unsigned int status; // ebx MAPDST
  unsigned int v7; // esi
  int (__fastcall *PsLookupThreadByThreadIdFn)(_QWORD, struct _KTHREAD **); // r13 MAPDST
  void (__fastcall *KeStackAttachProcessFn)(PEPROCESS, __int64 *); // rdi
  int v10; // eax
  void (*ObfDereferenceObjectFn)(void); // r15
  __int64 PsGetCurrentThreadIdFn; // r14 MAPDST
  size_t v14; // r13
  int v16; // ecx
  int OffsetKThreadStackLimit; // eax
  int OffsetKThreadStackBase; // eax
  int OffsetKThreadThreadLock; // eax
  unsigned int OffsetKThreadKernelStack; // eax
  __int64 OffsetKThreadKernelStack_1; // rdi
  unsigned int OffsetKThreadState; // eax
  __int64 OffsetKThreadState_1; // rsi
  int v24; // r14d
  const void **threadInitialStack; // rdi
  _BYTE *threadState; // rsi
  void *threadStackBase; // r15
  __int64 v28; // rdx
  void *threadCurrentStack; // rcx
  int v31; // r15d
  void *CurrentRip; // rdi
  void **Rsp; // rsi
  size_t i; // r14
  __int64 FunctionEntry; // rax
  size_t FrameIndex; // rax
  size_t v38; // r15
  unsigned int StackTraceThreadId; // r13d
  size_t y; // rdi
  unsigned __int64 currentStackFrame; // r14
  EMAC_MODULE_ENTRY *ModuleInfoFromAddress; // rsi
  __m128 si128; // xmm0
  unsigned __int64 lastStackFrame; // rax
  ULONG_PTR v45; // rdi
  unsigned int *v47; // r8
  ULONG_PTR *result; // rax
  bool largePage; // [rsp+40h] [rbp-C0h] BYREF
  int ThreadId; // [rsp+44h] [rbp-BCh]
  char CurrentIrql; // [rsp+48h] [rbp-B8h]
  struct _KTHREAD *Thread; // [rsp+58h] [rbp-A8h] MAPDST BYREF
  ULONG64 poolAddress; // [rsp+60h] [rbp-A0h] MAPDST
  void (*v55)(void); // [rsp+68h] [rbp-98h]
  int v56; // [rsp+70h] [rbp-90h]
  __int64 ImageBase; // [rsp+78h] [rbp-88h] BYREF
  size_t stackFramesCount; // [rsp+80h] [rbp-80h]
  PVOID FrameFileHeader; // [rsp+88h] [rbp-78h] BYREF
  void *HandlerData; // [rsp+A0h] [rbp-60h] BYREF
  char SubStr[16]; // [rsp+B0h] [rbp-50h] BYREF
  wchar_t Str2[8]; // [rsp+C0h] [rbp-40h] BYREF
  __m128 v65; // [rsp+D0h] [rbp-30h]
  unsigned __int8 (__fastcall *PsIsThreadTerminatingFn)(struct _KTHREAD *); // [rsp+E0h] [rbp-20h]
  void *threadStackLimit; // [rsp+E8h] [rbp-18h]
  __int64 (__stdcall *MmGetPhysicalAddressFn)(void *); // [rsp+F0h] [rbp-10h]
  unsigned __int8 (__fastcall *MmIsAddressValidFn_2)(const void *); // [rsp+F8h] [rbp-8h]
  __int64 threadLock; // [rsp+100h] [rbp+0h]
  void (__fastcall *KeReleaseSpinLockFn)(__int64, __int64); // [rsp+108h] [rbp+8h]
  _IMAGE_NT_HEADERS64 *ntoskrnlHeader; // [rsp+110h] [rbp+10h]
  BOOLEAN (__stdcall *MmIsAddressValidFn)(PVOID); // [rsp+118h] [rbp+18h] MAPDST
  __int64 (__fastcall *RtlLookupFunctionTableEntryFn)(void *, __int64 *, _QWORD); // [rsp+120h] [rbp+20h]
  void (__fastcall *RtlVirtualUnwindFn)(_QWORD, __int64, ULONG64, __int64, CONTEXT *, void **, DWORD64 *, _QWORD); // [rsp+128h] [rbp+28h]
  void (__fastcall *ExFreePoolWithTagFn)(ULONG64, _QWORD); // [rsp+130h] [rbp+30h]
  unsigned __int8 (__fastcall *MmIsAddressValidFn_1)(__int64); // [rsp+138h] [rbp+38h]
  void (__fastcall *RtlPcToFileHeaderFn)(unsigned __int64, PVOID *); // [rsp+140h] [rbp+40h]
  void (__fastcall *KeUnstackDetachProcessFn)(__int64 *); // [rsp+148h] [rbp+48h]
  struct _KTHREAD *CurrentThread; // [rsp+150h] [rbp+50h]
  __int128 EstablisherFrame; // [rsp+158h] [rbp+58h] BYREF
  __int64 (__fastcall *KeAcquireSpinLockRaiseToDpcFn)(__int64); // [rsp+168h] [rbp+68h]
  __m128i v83; // [rsp+170h] [rbp+70h] BYREF
  __m128 v84; // [rsp+180h] [rbp+80h]
  __m128i v85; // [rsp+190h] [rbp+90h] BYREF
  __int64 v86; // [rsp+1A0h] [rbp+A0h] BYREF
  __int128 v87; // [rsp+1A8h] [rbp+A8h]
  __int128 v88; // [rsp+1B8h] [rbp+B8h]
  unsigned __int64 baseAddress; // [rsp+1C8h] [rbp+C8h]
  __int64 stackFrames[32]; // [rsp+1D0h] [rbp+D0h] BYREF
  CONTEXT ContextRecord; // [rsp+2D0h] [rbp+1D0h] BYREF

  v4 = a4;
  status = 0;
  if ( KeGetCurrentIrql() > 1u )
  {
    v47 = (unsigned int *)(a4 + 0x30);
    status = 0xC0000148;
    result = (ULONG_PTR *)(a4 + 0x38);
    v45 = 0i64;
  }
  else
  {
    Thread = 0i64;
    v7 = 8;
    CurrentThread = KeGetCurrentThread();
    ThreadId = 8;
    baseAddress = 0i64;
    v86 = 0i64;
    v87 = 0i64;
    v88 = 0i64;
    memset(stackFrames, 0, sizeof(stackFrames));
    FrameFileHeader = 0i64;
    PsLookupThreadByThreadIdFn = (int (__fastcall *)(_QWORD, struct _KTHREAD **))(((unsigned __int64)PsLookupThreadByThreadId ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)PsLookupThreadByThreadId ^ qword_FFFFF801BCFACC40)));
    KeStackAttachProcessFn = (void (__fastcall *)(PEPROCESS, __int64 *))(((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)KeStackAttachProcess ^ qword_FFFFF801BCFACC40)));
    KeUnstackDetachProcessFn = (void (__fastcall *)(__int64 *))(((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)KeUnstackDetachProcess ^ qword_FFFFF801BCFACC40)));
    RtlPcToFileHeaderFn = (void (__fastcall *)(unsigned __int64, PVOID *))((RtlPcToFileHeader ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < (RtlPcToFileHeader ^ (unsigned __int64)qword_FFFFF801BCFACC40)));
    v10 = *(_DWORD *)(a1 + 0x3F8);
    MmIsAddressValidFn_1 = (unsigned __int8 (__fastcall *)(__int64))(((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40)));
    v56 = v10;
    ObfDereferenceObjectFn = (void (*)(void))(((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)ObfDereferenceObject ^ qword_FFFFF801BCFACC40)));
    v55 = ObfDereferenceObjectFn;
    if ( v10 >= 2 )
    {
      status = 0xC000000D;
      v45 = 0i64;
    }
    else
    {
      PsGetCurrentThreadIdFn = ((__int64 (*)(void))(((unsigned __int64)PsGetCurrentThreadId_0 ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)PsGetCurrentThreadId_0 ^ qword_FFFFF801BCFACC40))))();
      KeStackAttachProcessFn(g_AttachedProcess, &v86);
      if ( !g_UnknownThreadStartAddress )
        EmacGetThreadStartAddress(KeGetCurrentThread(), 0i64, &g_UnknownThreadStartAddress);
      do
      {
        if ( *(_BYTE *)(a1 + 2000) || g_EmacNotReady )
          break;
        if ( v7 != (_DWORD)PsGetCurrentThreadIdFn && PsLookupThreadByThreadIdFn(v7, &Thread) >= 0 )
        {
          if ( Thread != CurrentThread && EmacIsSystemThread(Thread) )
          {
            ntoskrnlHeader = RtlImageNtHeader((_IMAGE_DOS_HEADER *)g_NtoskrnlBase);
            ImageBase = 0i64;
            EstablisherFrame = 0ui64;
            v14 = 0i64;
            HandlerData = 0i64;
            memset(&ContextRecord, 0, sizeof(ContextRecord));
            largePage = 0;
            stackFramesCount = 0i64;
            memset(stackFrames, 0, sizeof(stackFrames));
            if ( Thread && ntoskrnlHeader )
            {
              MmIsAddressValidFn = (BOOLEAN (__stdcall *)(PVOID))(((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40)));
              RtlLookupFunctionTableEntryFn = (__int64 (__fastcall *)(void *, __int64 *, _QWORD))((qword_FFFFF801BCFACC40 ^ RtlLookupFunctionTableEntry) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)RtlLookupFunctionTableEntry)));
              RtlVirtualUnwindFn = (void (__fastcall *)(_QWORD, __int64, ULONG64, __int64, CONTEXT *, void **, DWORD64 *, _QWORD))((qword_FFFFF801BCFACC40 ^ RtlVirtualUnwind) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)RtlVirtualUnwind)));
              ExFreePoolWithTagFn = (void (__fastcall *)(ULONG64, _QWORD))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)ExFreePoolWithTag) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)ExFreePoolWithTag)));
              poolAddress = ((__int64 (__fastcall *)(_QWORD, __int64, _QWORD))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)ExAllocatePoolWithTag) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)ExAllocatePoolWithTag))))(
                              (unsigned int)g_EmacPoolType,
                              0x2000i64,
                              'CAME');
              if ( poolAddress )
              {
                v16 = dword_FFFFF801BCFCC174;
                if ( (dword_FFFFF801BCFCC174 & 1) == 0 )
                {
                  dword_FFFFF801BCFCC174 |= 1u;
                  OffsetKThreadStackLimit = GetOffsetKThreadStackLimit();
                  v16 = dword_FFFFF801BCFCC174;
                  g_OffsetKThreadStackLimit = OffsetKThreadStackLimit;
                }
                if ( (v16 & 2) == 0 )
                {
                  dword_FFFFF801BCFCC174 = v16 | 2;
                  OffsetKThreadStackBase = GetOffsetKThreadStackBase();
                  v16 = dword_FFFFF801BCFCC174;
                  g_OffsetKThreadStackBase = OffsetKThreadStackBase;
                }
                if ( (v16 & 4) == 0 )
                {
                  dword_FFFFF801BCFCC174 = v16 | 4;
                  OffsetKThreadThreadLock = GetOffsetKThreadThreadLock();
                  v16 = dword_FFFFF801BCFCC174;
                  g_OffsetKThreadThreadLock = OffsetKThreadThreadLock;
                }
                if ( (v16 & 8) != 0 )
                {
                  OffsetKThreadKernelStack_1 = (unsigned int)g_OffsetKThreadKernelStack;
                }
                else
                {
                  dword_FFFFF801BCFCC174 = v16 | 8;
                  OffsetKThreadKernelStack = GetOffsetKThreadKernelStack();
                  v16 = dword_FFFFF801BCFCC174;
                  OffsetKThreadKernelStack_1 = OffsetKThreadKernelStack;
                  g_OffsetKThreadKernelStack = OffsetKThreadKernelStack;
                }
                if ( (v16 & 0x10) != 0 )
                {
                  OffsetKThreadState_1 = (unsigned int)g_OffsetKThreadState;
                }
                else
                {
                  dword_FFFFF801BCFCC174 = v16 | 0x10;
                  OffsetKThreadState = GetOffsetKThreadState();
                  OffsetKThreadKernelStack_1 = (unsigned int)g_OffsetKThreadKernelStack;
                  OffsetKThreadState_1 = OffsetKThreadState;
                  g_OffsetKThreadState = OffsetKThreadState;
                }
                MmIsAddressValidFn_2 = (unsigned __int8 (__fastcall *)(const void *))(((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40) & -(__int64)(qword_FFFFF801BCFACC38 < ((unsigned __int64)MmIsAddressValid ^ qword_FFFFF801BCFACC40)));
                MmGetPhysicalAddressFn = (__int64 (__stdcall *)(void *))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)MmGetPhysicalAddress) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)MmGetPhysicalAddress)));
                KeAcquireSpinLockRaiseToDpcFn = (__int64 (__fastcall *)(__int64))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)KeAcquireSpinLockRaiseToDpc) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)KeAcquireSpinLockRaiseToDpc)));
                KeReleaseSpinLockFn = (void (__fastcall *)(__int64, __int64))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)KeReleaseSpinLock) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)KeReleaseSpinLock)));
                PsIsThreadTerminatingFn = (unsigned __int8 (__fastcall *)(struct _KTHREAD *))((qword_FFFFF801BCFACC40 ^ (unsigned __int64)PsIsThreadTerminating) & -(__int64)(qword_FFFFF801BCFACC38 < (qword_FFFFF801BCFACC40 ^ (unsigned __int64)PsIsThreadTerminating)));
                KeGetCurrentIrql();
                v24 = 0;
                memset((void *)poolAddress, 0, 0x2000ui64);
                if ( g_OffsetKThreadStackLimit == -1
                  || g_OffsetKThreadStackBase == -1
                  || g_OffsetKThreadThreadLock == -1
                  || (_DWORD)OffsetKThreadKernelStack_1 == -1
                  || (_DWORD)OffsetKThreadState_1 == -1 )
                {
                  v31 = 0xC0000138;
                }
                else
                {
                  threadInitialStack = (const void **)((char *)Thread + OffsetKThreadKernelStack_1);
                  threadState = (char *)Thread + OffsetKThreadState_1;
                  threadStackBase = *(void **)((char *)Thread + (unsigned int)g_OffsetKThreadStackBase);
                  threadStackLimit = *(void **)((char *)Thread + (unsigned int)g_OffsetKThreadStackLimit);
                  threadLock = (__int64)Thread + (unsigned int)g_OffsetKThreadThreadLock;
                  CurrentIrql = KeAcquireSpinLockRaiseToDpcFn(threadLock);
                  if ( PsIsThreadTerminatingFn(Thread) || *threadState != 5 )
                  {
                    v24 = 0xC000004B;
                  }
                  else
                  {
                    threadCurrentStack = (void *)*threadInitialStack;
                    if ( *threadInitialStack > threadStackLimit
                      && threadCurrentStack < threadStackBase
                      && MmGetPhysicalAddressFn(threadCurrentStack)
                      && MmIsAddressValidFn_2(*threadInitialStack) )
                    {
                      v14 = (_BYTE *)threadStackBase - (_BYTE *)*threadInitialStack;
                      if ( v14 > 0x2000 )
                        v14 = 0x2000i64;
                      memmove_2((void *)poolAddress, *threadInitialStack, v14);
                    }
                    else
                    {
                      v24 = 0xC0000141;
                    }
                  }
                  LOBYTE(v28) = CurrentIrql;
                  KeReleaseSpinLockFn(threadLock, v28);
                  v31 = v24;
                  if ( v24 >= 0
                    && v14 - 73 <= 8118
                    && EmacVerifyInTextSection(*(_QWORD *)(poolAddress + 0x38), (__int64)g_NtoskrnlBase, ntoskrnlHeader) )
                  {
                    memset(&ContextRecord, 0, sizeof(ContextRecord));
                    CurrentRip = *(void **)(poolAddress + 0x38);
                    Rsp = (void **)(poolAddress + 0x40);
                    i = stackFramesCount;
                    ContextRecord.Rsp = (ULONG64)Rsp;
                    ContextRecord.Rip = (ULONG64)CurrentRip;
                    do
                    {
                      ImageBase = 0i64;
                      HandlerData = 0i64;
                      EstablisherFrame = 0i64;
                      if ( (unsigned __int64)CurrentRip <= qword_FFFFF801BCFACC38 )
                        break;
                      if ( (unsigned __int64)Rsp <= qword_FFFFF801BCFACC38 )
                        break;
                      if ( !MmIsAddressValidFn(CurrentRip) )
                        break;
                      if ( !MmIsAddressValidFn(Rsp) )
                        break;
                      largePage = 0;
                      if ( !EmacIsPageEntryValid((__int64)CurrentRip, &largePage, 0i64) )
                        break;
                      if ( largePage )
                        break;
                      stackFrames[i] = (__int64)CurrentRip;
                      if ( !EmacGetModuleInfoFromAddress((unsigned __int64)CurrentRip, 1) )
                        break;
                      FunctionEntry = RtlLookupFunctionTableEntryFn(CurrentRip, &ImageBase, 0i64);
                      if ( FunctionEntry )
                      {
                        RtlVirtualUnwindFn(
                          0i64,
                          ImageBase,
                          ContextRecord.Rip,
                          FunctionEntry,
                          &ContextRecord,
                          &HandlerData,
                          (DWORD64 *)&EstablisherFrame,
                          0i64);
                        CurrentRip = (void *)ContextRecord.Rip;
                        Rsp = (void **)ContextRecord.Rsp;
                      }
                      else
                      {
                        CurrentRip = *Rsp;
                        Rsp = (void **)(ContextRecord.Rsp + 8);
                        ContextRecord.Rip = (ULONG64)CurrentRip;
                        ContextRecord.Rsp += 8i64;
                      }
                      FrameIndex = i++;
                      stackFramesCount = i;
                      if ( FrameIndex >= 32 )
                        break;
                    }
                    while ( (unsigned __int64)CurrentRip >= qword_FFFFF801BCFACC38 && !g_EmacNotReady );
                  }
                }
                ExFreePoolWithTagFn(poolAddress, 'CAME');
                if ( v31 < 0 || (v38 = stackFramesCount, stackFramesCount - 1 > 31) )
                {
                  v7 = ThreadId;
                }
                else
                {
                  StackTraceThreadId = ThreadId;
                  y = 0i64;
                  do
                  {
                    if ( *(_BYTE *)(a1 + 0x7D0) )
                      break;
                    if ( g_EmacNotReady )
                      break;
                    currentStackFrame = stackFrames[y];
                    if ( currentStackFrame <= qword_FFFFF801BCFACC38 || !MmIsAddressValidFn_1(stackFrames[y]) )
                      break;
                    ModuleInfoFromAddress = EmacGetModuleInfoFromAddress(currentStackFrame, 1);
                    RtlPcToFileHeaderFn(currentStackFrame, &FrameFileHeader);
                    if ( ModuleInfoFromAddress )
                    {
                      if ( FrameFileHeader != ModuleInfoFromAddress->ImageBase )
                        break;
                      if ( ModuleInfoFromAddress->SubjectName[0] )
                      {
                        *(_QWORD *)Str2 = 0xB07F113F97FF5772ui64;
                        *(_QWORD *)&Str2[4] = 0x13112D07CA8DB1F8i64;
                        si128 = (__m128)_mm_load_si128((const __m128i *)Str2);
                        v65.m128_u64[0] = 0x77B95CDEC3F425C2i64;
                        v84.m128_u64[0] = 0xD6106250E59C3E3Fui64;
                        v65.m128_u64[1] = 0xA8723627E07A05FEui64;
                        v84.m128_u64[1] = 0x647E4969A3DA918Ci64;
                        v85.m128i_i64[1] = 0xA8723627E07A05FEui64;
                        v85.m128i_i64[0] = 0x77B95CDEC3F425B1i64;
                        v65 = _mm_xor_ps((__m128)_mm_load_si128(&v85), v65);// Decrypted UTF-8: s
                        *(__m128 *)Str2 = _mm_xor_ps(si128, v84);// Decrypted Raw (unprintable): 44 85 40 94 3f 11 7f b0 74 20 57 69 6e 64 6f 77
                        if ( strcmp(ModuleInfoFromAddress->SubjectName, (const char *)Str2) )// "Microsoft Corporation"
                          break;
                      }
                      if ( ModuleInfoFromAddress->AdditionalData[0] )
                      {
                        *(_QWORD *)SubStr = 0xB364033495E95D52ui64;
                        v83.m128i_i64[0] = 0xD6106250E59C3E3Fui64;
                        *(_QWORD *)&SubStr[8] = 0x647E4969A3DA918Ci64;
                        v83.m128i_i64[1] = 0x647E4969A3DA918Ci64;
                        *(__m128 *)SubStr = _mm_xor_ps((__m128)_mm_load_si128(&v83), *(__m128 *)SubStr);
                        if ( strstr((const char *)ModuleInfoFromAddress->AdditionalData, SubStr) )// "mcupdate"
                          break;
                      }
                    }
                    if ( v56 )
                    {
                      if ( v56 == 1
                        && ModuleInfoFromAddress
                        && !EmacIsAddressInCodeSectionRange(
                              currentStackFrame,
                              (_IMAGE_DOS_HEADER *)ModuleInfoFromAddress->ImageBase,
                              0i64) )
                      {
                        EmacReportThreadInvalidStackTrace_2(
                          Thread,
                          (__int64)g_UnknownThreadStartAddress,
                          StackTraceThreadId,
                          y,
                          v38,
                          currentStackFrame,
                          (__int64)ModuleInfoFromAddress,
                          a1);
                      }
                    }
                    else if ( !ModuleInfoFromAddress && !FrameFileHeader )
                    {
                      if ( y && y < v38 )
                        lastStackFrame = stackFrames[y - 1];
                      else
                        lastStackFrame = 0i64;
                      EmacReportThreadInvalidStackTrace(
                        Thread,
                        g_UnknownThreadStartAddress,
                        StackTraceThreadId,
                        y,
                        v38,
                        currentStackFrame,
                        lastStackFrame,
                        a1);
                    }
                    ++y;
                  }
                  while ( y <= v38 );
                  v7 = StackTraceThreadId;
                }
              }
              else
              {
                v7 = ThreadId;
              }
              ObfDereferenceObjectFn = v55;
            }
            else
            {
              v7 = ThreadId;
            }
          }
          ObfDereferenceObjectFn();
        }
        v7 += 4;
        ThreadId = v7;
        EmacDelayExecutionThread(1);
      }
      while ( v7 < 0x10000 );
      KeUnstackDetachProcessFn(&v86);
      v45 = 2008i64;
      if ( a3 < 2008 )
        status = 0xC0000004;
      else
        memmove_2(a2, (const void *)a1, 2008ui64);
      v4 = a4;
    }
    v47 = (unsigned int *)(v4 + 0x30);
    result = (ULONG_PTR *)(v4 + 0x38);
  }
  *result = v45;
  *v47 = status;
  return result;
}
```

The routine `EmacGetThreadStartAddress` queues an work item which will retrieve the thread start address, it is then verified if that address resides in any `ntoskrnl.exe` code section.

Now the NMI callback registration
![img](/assets/img/emac-anticheat-driver-part6/nmi.png)

_sadly goes to a vmenter, we cannot reverse any further_
![img](/assets/img/emac-anticheat-driver-part6/virt.png)

## Self integrity

I have spotted some procedures that will perform self-integrity checks in the driver.

_this function finds driver file path using registry and reads the file contents into a buffer_
![img](/assets/img/emac-anticheat-driver-part6/1.png)

_then relocations are stored in a list_
![img](/assets/img/emac-anticheat-driver-part6/2.png)

_and finally, the buffer contents are xored with a simple key_
![img](/assets/img/emac-anticheat-driver-part6/3.png)

_this function will decrypt the buffer into a copy_
![img](/assets/img/emac-anticheat-driver-part6/4.png)

_this function will perform 1:1 integrity check between the memory and the file sections on disk_
![img](/assets/img/emac-anticheat-driver-part6/5.png)


Here's the list of things that the anticheat is doing:

- Checks `MmUnloadedDrivers` and `PiDDBCache`, those lists contains informations about kernel drivers loaded by the system
- Checks if system images sections have the right PTE flags by iterating `PsLoadedModuleList` and comparing with the PE information from disk
- Checks if processes have `\Device\PhysicalMemory` handle
- Checks if some functions from `HalPrivateDispatchTable` are being tampered
- Self-integrity checks at `.text` (code) and `.idata` (IAT), by comparing with the PE file on disk
- Checks `gDxgkInterface` table from module `win32kbase.sys`, this table is oftenly used as what we call `.data` pointer hooks.
- Enumerate all system handles and strip access mask from any unauthorized process
- Actively walk throught system pages and perform physical memory dumps based on the PTE flags, this can be used to detect manually mapped drivers.
- Iterate BigPool list, searches for known malicious tags.
- Scans usermode process memory for patterns.

That's all i could find but there must be a lot more scans and checks sitting in virtualized code.

# IDA decompiled snippets

[Integrity Snippets](https://github.com/crvvdev/emaclab-reversal/blob/main/integrity.c)