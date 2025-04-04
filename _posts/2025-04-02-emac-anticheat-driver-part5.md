---
title: "EMACLAB Anticheat Driver, Part 5: Filter and Callbacks"
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

# Callbacks

Callbacks for threads, processes and images are registered, the only handler i could find without virtualization was image callback.

The image callback is a huge function, it will insert the newly module into a internal list, then some actions are done, such as:

- Get ntdll.dll addresses (DbgBreakPoint, DbgUiRemoteBreak, DbgUserBreakPoint, LdrLoadDll)
- Get kernel32.dll addresses (LoadLibraryA, LoadLibraryW, LoadLibraryExA, LoadLibraryExW)
- Get kernelbase.dll addresses (LoadLibraryA, LoadLibraryW, LoadLibraryExA, LoadLibraryExW)
- Get cs2.exe base and size, as well as engine2.dll base and size
- Get GamersClub launcher image base
- Will load EMAC-CSGO-x64.dll into the game process via driver using `NtCreateThreadEx` and `KERNEL32.DLL!LoadLibraryW` 

_You must think, if the driver loads the .DLL then i can simply overwrite it on disk so it loads my own, but remember there's a minifilter with file signature checks:_

# Minifilter

EMACLAB Anticheat registers a __FSFilter Activity Monitor__ with altitude __363570__.
Then a pre-operation callback is set on memory section creation, to intercept system image loading.

The whole file signature verification is done in kernel using CI.dll APIs.

```cpp
__int64 __fastcall EmacFltCallback(PFLT_CALLBACK_DATA fltCallbackData)
{
  unsigned int v2; // ebp
  ULONG (__fastcall *FltGetRequestorProcessIdFn)(PFLT_CALLBACK_DATA); // rsi
  NTSTATUS (__fastcall *FltGetFileNameInformationFn)(PFLT_CALLBACK_DATA, FLT_FILE_NAME_OPTIONS, PFLT_FILE_NAME_INFORMATION *); // r12
  NTSTATUS (__fastcall *FltParseFileNameInformationFn)(PFLT_FILE_NAME_INFORMATION); // r15
  NTSTATUS (__stdcall *FltReleaseFileNameInformationFn)(PFLT_FILE_NAME_INFORMATION); // r14
  PFLT_IO_PARAMETER_BLOCK Iopb; // rdi
  ULONG processId; // esi
  struct _FLT_FILE_NAME_INFORMATION *v9; // rcx
  PFLT_FILE_NAME_INFORMATION fileNameInformation; // [rsp+50h] [rbp+8h] BYREF

  v2 = 1;
  _InterlockedAdd(&g_EmacReferenceCount, 1u);
  fileNameInformation = 0i64;
  FltGetRequestorProcessIdFn = (ULONG (__fastcall *)(PFLT_CALLBACK_DATA))(((unsigned __int64)FltGetRequestorProcessId ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltGetRequestorProcessId ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  FltGetFileNameInformationFn = (NTSTATUS (__fastcall *)(PFLT_CALLBACK_DATA, FLT_FILE_NAME_OPTIONS, PFLT_FILE_NAME_INFORMATION *))(((unsigned __int64)FltGetFileNameInformation ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltGetFileNameInformation ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  FltParseFileNameInformationFn = (NTSTATUS (__fastcall *)(PFLT_FILE_NAME_INFORMATION))(((unsigned __int64)FltParseFileNameInformation ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltParseFileNameInformation ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  FltReleaseFileNameInformationFn = (NTSTATUS (__stdcall *)(PFLT_FILE_NAME_INFORMATION))(((unsigned __int64)FltReleaseFileNameInformation ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltReleaseFileNameInformation ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  if ( fltCallbackData )
  {
    Iopb = fltCallbackData->Iopb;
    if ( Iopb )
    {
      if ( Iopb->Parameters.Read.Length == 1 && Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == 0x10 )
      {
        ((void (__fastcall *)(PFLT_CALLBACK_DATA))(((unsigned __int64)FltGetRequestorProcess ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)FltGetRequestorProcess ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38)))(fltCallbackData);
        processId = FltGetRequestorProcessIdFn(fltCallbackData);
        if ( (processId == 4 || g_GameProcessId && processId == (_DWORD)g_GameProcessId)
          && (FltGetFileNameInformationFn(fltCallbackData, 0x101i64, &fileNameInformation) & 0xC0000000) != 0xC0000000
          && (FltParseFileNameInformationFn(fileNameInformation) & 0xC0000000) != 0xC0000000
          && processId == 4
          && EmacFltVerifyFileName(Iopb, fileNameInformation) )
        {
          fltCallbackData->IoStatus.Information = 0i64;
          v2 = 4;
          v9 = fileNameInformation;
          fltCallbackData->IoStatus.Status = 0xC000009A;// Block from loading
          if ( !v9 )
            goto LABEL_17;
        }
        else
        {
          v9 = fileNameInformation;
        }
        if ( v9 )
          FltReleaseFileNameInformationFn(v9);
      }
    }
  }
LABEL_17:
  _InterlockedDecrement(&g_EmacReferenceCount);
  return v2;
}
```

They proceed to verify the file, based on name and code signature informations.

```cpp
bool __fastcall EmacFltVerifyFileName(PFLT_IO_PARAMETER_BLOCK Iopb, PFLT_FILE_NAME_INFORMATION fileNameInformation)
{
  char v3; // di
  void (__fastcall *ExFreePoolWithTagFn)(_IMAGE_DOS_HEADER *, _QWORD); // r14
  _IMAGE_DOS_HEADER *fileBuffer; // rbx
  __int64 e_lfanew; // rax
  _EMAC_IMAGE_SIGN_INFO a3; // [rsp+20h] [rbp-E0h] BYREF
  unsigned __int64 fileSize; // [rsp+310h] [rbp+210h] BYREF

  LODWORD(fileSize) = 0;
  *(_QWORD *)&a3.VerificationStatus = 0i64;
  a3.PolicyInfoSize = 0;
  v3 = 0;
  a3.IsVerified = 0;
  memset(&a3.SigningTime, 0, 681);
  ExFreePoolWithTagFn = (void (__fastcall *)(_IMAGE_DOS_HEADER *, _QWORD))(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExFreePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));
  if ( !byte_FFFFF801BCFAC6D8 )                 // Probably a master switch for file verification
  {
    if ( fileNameInformation && EmacCheckDbkProcessHackerByFileName(&fileNameInformation->Name) )
    {
      return 1;
    }
    else
    {
      fileBuffer = (_IMAGE_DOS_HEADER *)EmacFltReadFileToBuffer(Iopb->TargetInstance, Iopb->TargetFileObject, &fileSize);
      if ( fileBuffer )
      {
        if ( fileBuffer->e_magic == 0x5A4D )
        {
          e_lfanew = fileBuffer->e_lfanew;
          if ( (int)e_lfanew < 4096
            && (unsigned int)fileSize > 0x1000
            && *(_DWORD *)((char *)&fileBuffer->e_magic + e_lfanew) == 0x4550
            && *(USHORT *)((char *)&fileBuffer->e_lfarlc + e_lfanew) == 0x20B
            && *(USHORT *)((char *)fileBuffer[1].e_res + e_lfanew) == 1 )// Validate PE
          {
            if ( EmacVerifyFileSigned(fileBuffer, (unsigned int)fileSize, &a3) >= 0
              && LOBYTE(a3.Unknown1)
              && EmacVerifyFileCertificateName(a3.SubjectName) )
            {
              v3 = 1;
            }
            else
            {
              v3 = EmacVerifyFileUnknown((__int64)fileBuffer);
            }
          }
        }
        ExFreePoolWithTagFn(fileBuffer, 'CAME');
      }
    }
  }
  return v3;
}
```

`EmacCheckSystemImageByName` will verify if image name is `dbk64.sys`/`dbk32.sys` (Cheat Engine) or `kprocesshacker2.sys` (Process Hacker):

_this is kinda of meme since it checks purely by the file name, you can try renaming a legitimate non-malicious driver and try load it to see what happens_
```cpp
bool __fastcall EmacCheckDbkProcessHacker(const wchar_t *imageName)
{
  unsigned __int64 v1; // rbx
  __m128 v2; // rdi
  unsigned __int64 v4; // r8
  unsigned __int64 v5; // r8
  __m128 si128; // xmm0
  __m128 v7; // xmm1
  __int64 v8; // rbx
  __int64 *v9; // rsi
  bool v10; // di
  __int64 i; // rbx
  wchar_t *v12; // rdx
  __m128 v14; // [rsp+20h] [rbp-69h] BYREF
  __m128 v15; // [rsp+30h] [rbp-59h] BYREF
  __m128 v16; // [rsp+40h] [rbp-49h] BYREF
  __m128 v17; // [rsp+50h] [rbp-39h]
  __int128 v18[2]; // [rsp+60h] [rbp-29h] BYREF
  __int128 v19[2]; // [rsp+80h] [rbp-9h] BYREF
  __int128 v20[2]; // [rsp+A0h] [rbp+17h] BYREF
  char v21[32]; // [rsp+C0h] [rbp+37h] BYREF
  char *v22; // [rsp+F8h] [rbp+6Fh] BYREF
  __int128 *v23; // [rsp+100h] [rbp+77h] BYREF

  v1 = -1i64;
  v16.m128_u64[0] = 0xA5AE4945064F9i64;
  v2.m128_u64[0] = 0x3C5A8F9432649Di64;
  v14.m128_u64[0] = 0x3C5A8F9432649Di64;
  v16.m128_u64[1] = 0x3AD429636D08232i64;
  v2.m128_u64[1] = 0x3AD429636D08206i64;
  v14.m128_u64[1] = 0x3AD429636D08206i64;
  v16 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v14), v16);// Decrypted UTF-16: dbk64
  v4 = -1i64;
  memset(v18, 0, sizeof(v18));
  do
    ++v4;
  while ( v16.m128_i16[v4] );
  std_vector_push_back(v18, &v16, v4);
  v14 = v2;
  v16.m128_u64[0] = 0xF5AE4945064F9i64;
  v16.m128_u64[1] = 0x3AD429636D08234i64;
  v5 = -1i64;
  v16 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v16), v2);// Decrypted UTF-16: dbk34
  memset(v19, 0, sizeof(v19));
  do
    ++v5;
  while ( v16.m128_i16[v5] );
  std_vector_push_back(v19, &v16, v5);
  v16 = v2;
  v14.m128_u64[0] = 0x535AFD944264F6i64;
  v14.m128_u64[1] = 0x3DE42E536B58265i64;
  si128 = (__m128)_mm_load_si128((const __m128i *)&v14);
  v15.m128_u64[0] = 0x454DEBE66E3527A7i64;
  v15.m128_u64[1] = 0x3C2843EC1561C2DDi64;
  v7 = (__m128)_mm_load_si128((const __m128i *)&v15);
  v17.m128_u64[0] = 0x4526EB856E5427CFi64;
  v17.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v15 = _mm_xor_ps(v7, v17);                    // Decrypted Raw (unprintable): 51 43 77 fa 1b b1 1e 45 65 00 72 00 00 00 00 00
  v14 = _mm_xor_ps(si128, v2);                  // Decrypted UTF-16: kpro2
  memset(v20, 0, sizeof(v20));                  // L"kprocesshacker"
  do
    ++v1;
  while ( v14.m128_i16[v1] );
  std_vector_push_back(v20, &v14, v1);
  v15.m128_u64[0] = 0i64;
  v22 = v21;
  v8 = 3i64;
  v23 = v18;
  v14 = 0i64;
  std_vector_alloc_3((unsigned __int64 *)&v14, 3ui64, &v23, &v22);
  v9 = (__int64 *)v21;
  v10 = 1;
  do
  {
    v9 -= 4;
    sub_FFFFF801BCEF4B20(v9);
    --v8;
  }
  while ( v8 );
  for ( i = v14.m128_u64[0]; i != v14.m128_u64[1]; i += 32i64 )// // this is basically a range based loop to traverse vector elements
  {
    v12 = (wchar_t *)i;
    if ( *(_QWORD *)(i + 24) > 7ui64 )
      v12 = *(wchar_t **)i;
    if ( wcsistr((wchar_t *)imageName, v12) )
      goto LABEL_16;
  }
  v10 = 0;
LABEL_16:
  sub_FFFFF801BCEF4A94((__int64)&v14);
  return v10;
}
```

The next function goes beyong and verifies the file signature with known malicious subject names:

_I am sorry, the static xor string decipher oftenly puts the words out of order_
```cpp
bool __fastcall EmacVerifyFileCertificateName(char *subjectName)
{
  __int64 v1; // rdi
  __int64 v3; // r8
  bool v4; // bl
  __int64 v5; // r8
  __int64 v6; // r8
  __int64 v7; // r8
  __int64 v8; // r8
  __int64 v9; // r8
  __m128 v10; // xmm0
  __int64 v11; // r8
  __m128 si128; // xmm1
  __int64 v13; // r8
  __m128 v14; // xmm0
  __m128 v15; // xmm1
  __m128 v16; // xmm0
  __int64 v17; // r8
  __int64 v18; // r8
  __m128 v19; // xmm0
  __m128 v20; // xmm1
  __m128 v21; // xmm0
  __int64 v22; // r8
  __m128 v23; // xmm0
  __m128 v24; // xmm1
  __m128 v25; // xmm0
  __int64 v26; // r8
  __m128 v27; // xmm0
  __m128 v28; // xmm1
  __m128 v29; // xmm0
  __int64 v30; // r8
  __m128 v31; // xmm0
  __m128 v32; // xmm1
  __int64 v33; // r8
  __m128 v34; // xmm0
  __m128 v35; // xmm1
  __m128 v36; // xmm0
  __int64 v37; // r14
  __int64 *v38; // rdi
  char v39; // si
  unsigned __int64 v40; // rdx
  __int64 v41; // rcx
  __int64 v42; // r8
  const char *v43; // rcx
  __int64 i; // rdi
  char *v45; // rdx
  __m128 v47; // [rsp+20h] [rbp-E0h] BYREF
  __m128 v48; // [rsp+30h] [rbp-D0h] BYREF
  __m128 v49; // [rsp+40h] [rbp-C0h] BYREF
  __m128 v50; // [rsp+50h] [rbp-B0h] BYREF
  __m128 v51; // [rsp+60h] [rbp-A0h] BYREF
  __m128 v52; // [rsp+70h] [rbp-90h]
  __m128 v53; // [rsp+80h] [rbp-80h]
  __m128 v54; // [rsp+90h] [rbp-70h]
  __int128 v55[2]; // [rsp+A0h] [rbp-60h] BYREF
  __int128 v56[2]; // [rsp+C0h] [rbp-40h] BYREF
  __int128 v57[2]; // [rsp+E0h] [rbp-20h] BYREF
  __int128 v58[2]; // [rsp+100h] [rbp+0h] BYREF
  __int128 v59[2]; // [rsp+120h] [rbp+20h] BYREF
  __int128 v60[2]; // [rsp+140h] [rbp+40h] BYREF
  __int128 v61[2]; // [rsp+160h] [rbp+60h] BYREF
  __int128 v62[2]; // [rsp+180h] [rbp+80h] BYREF
  __int128 v63[2]; // [rsp+1A0h] [rbp+A0h] BYREF
  __int128 v64[2]; // [rsp+1C0h] [rbp+C0h] BYREF
  __int128 v65[2]; // [rsp+1E0h] [rbp+E0h] BYREF
  __int128 v66[2]; // [rsp+200h] [rbp+100h] BYREF
  __int128 v67[2]; // [rsp+220h] [rbp+120h] BYREF
  __int128 v68[2]; // [rsp+240h] [rbp+140h] BYREF
  __int128 v69[2]; // [rsp+260h] [rbp+160h] BYREF
  char v70[48]; // [rsp+280h] [rbp+180h] BYREF
  char *v71; // [rsp+2C8h] [rbp+1C8h] BYREF
  __int128 *v72; // [rsp+2D0h] [rbp+1D0h] BYREF

  v1 = -1i64;
  v51.m128_u64[0] = 0x6E797AFBF5570CDEi64;
  v47.m128_u64[0] = 0x3C5A8F9432649Di64;
  v51.m128_u64[1] = 0x3AD429653BEEB61i64;
  v47.m128_u64[1] = 0x3AD429636D08206i64;
  v51 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v51), v47);// Decrypted UTF-8: Cheat Engine
  v3 = -1i64;
  memset(v55, 0, sizeof(v55));
  v4 = 0;
  do
    ++v3;
  while ( v51.m128_i8[v3] );
  sub_FFFFF801BCEF2B2C(v55, &v51);
  v47.m128_u64[0] = 0x3C5A8F9432649Di64;
  v51.m128_u64[0] = 0x6E5537EEFE5C01DFi64;
  v47.m128_u64[1] = 0x3AD429636D08206i64;
  v51.m128_u64[1] = 0x3AD3BE65AB5C626i64;
  v5 = -1i64;
  v51 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v51), v47);// Decrypted UTF-8: Benjamingine
  memset(v56, 0, sizeof(v56));
  do
    ++v5;
  while ( v51.m128_i8[v5] );
  sub_FFFFF801BCEF2B2C(v56, &v51);
  v47.m128_u64[0] = 0x3C5A8F9432649Di64;
  v51.m128_u64[0] = 0x205D33C5B45C01CAi64;
  v47.m128_u64[1] = 0x3AD429636D08206i64;
  v51.m128_u64[1] = 0x3AD429636A5EB4Ai64;
  v6 = -1i64;
  v51 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v51), v47);// Decrypted UTF-8: Wen Jia  Delpy
  memset(v57, 0, sizeof(v57));
  do
    ++v6;
  while ( v51.m128_i8[v6] );
  sub_FFFFF801BCEF2B2C(v57, &v51);
  v47.m128_u64[0] = 0x3C5A8F9432649Di64;
  v51.m128_u64[0] = 0x6D5511E8FA5D0CDEi64;
  v47.m128_u64[1] = 0x3AD429636D08206i64;
  v51.m128_u64[1] = 0x3AD42F857B8C126i64;
  v7 = -1i64;
  v51 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v51), v47);// Decrypted UTF-8: ChongKimLiu
  memset(v58, 0, sizeof(v58));
  do
    ++v7;
  while ( v51.m128_i8[v7] );
  sub_FFFFF801BCEF2B2C(v58, &v51);
  v47.m128_u64[0] = 0x3C5A8F9432649Di64;
  v51.m128_u64[0] = 0x4B6E1BC7C76621D3i64;
  v47.m128_u64[1] = 0x3AD429636D08206i64;
  v51.m128_u64[1] = 0x3AD42FA51B1D126i64;
  v8 = -1i64;
  v51 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v51), v47);// Decrypted UTF-8: NETSHARK Chan
  memset(v59, 0, sizeof(v59));
  do
    ++v8;
  while ( v51.m128_i8[v8] );
  sub_FFFFF801BCEF2B2C(v59, &v51);
  v47.m128_u64[0] = 0x3C5A8F9432649Di64;
  v51.m128_u64[0] = 0x547D1FC7D76134DBi64;
  v47.m128_u64[1] = 0x3AD429636D08206i64;
  v51.m128_u64[1] = 0x3AD429636D08255i64;
  v9 = -1i64;
  v51 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v51), v47);// Decrypted UTF-8: FPSCHEAT Sagl
  memset(v60, 0, sizeof(v60));
  do
    ++v9;
  while ( v51.m128_i8[v9] );
  sub_FFFFF801BCEF2B2C(v60, &v51);
  v51.m128_u64[0] = 0x3C5A8F9432649Di64;
  v47.m128_u64[0] = 0x6D4934E6E05308CDi64;
  v51.m128_u64[1] = 0x3AD429636D08206i64;
  v47.m128_u64[1] = 0x6FCC36FF51B9C626i64;
  v10 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v47), v51);
  v11 = -1i64;
  v48.m128_u64[0] = 0x9069BF0012660EFi64;
  v48.m128_u64[1] = 0x3C2843EC151381F4i64;
  si128 = (__m128)_mm_load_si128((const __m128i *)&v48);
  v52.m128_u64[0] = 0x4526EB856E5427CFi64;
  v52.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v48 = _mm_xor_ps(si128, v52);                 // Decrypted Raw (unprintable): 72 04 14 95 7f c1 3a 09 4c 43 00 00 00 00 00 00
  v47 = v10;                                    // Decrypted UTF-8: PlatinumS
  memset(v61, 0, sizeof(v61));
  do
    ++v11;
  while ( v47.m128_i8[v11] );
  sub_FFFFF801BCEF2B2C(v61, &v47);
  v48.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v47.m128_u64[0] = 0x531C12CCD16636D7i64;
  v13 = -1i64;
  v51.m128_u64[0] = 0x3C5A8F9432649Di64;
  v47.m128_u64[1] = 0x23E30DDF6285CE49i64;
  v14 = (__m128)_mm_load_si128((const __m128i *)&v47);
  v48.m128_u64[0] = 0x4526EB856E546282i64;
  v15 = (__m128)_mm_load_si128((const __m128i *)&v48);
  v51.m128_u64[1] = 0x3AD429636D08206i64;
  v52.m128_u64[0] = 0x4526EB856E5427CFi64;
  v52.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v48 = _mm_xor_ps(v15, v52);                   // Decrypted UTF-8: ME
  v47 = _mm_xor_ps(v14, v51);                   // Decrypted UTF-8: JRTECH S Digital
  memset(v62, 0, sizeof(v62));
  do
    ++v13;
  while ( v47.m128_i8[v13] );
  sub_FFFFF801BCEF2B2C(v62, &v47);
  v51.m128_u64[1] = 0x3AD429636D08206i64;
  v51.m128_u64[0] = 0x3C36FDC71230D5i64;
  v16 = (__m128)_mm_load_si128((const __m128i *)&v51);
  v47.m128_u64[0] = 0x3C5A8F9432649Di64;
  v17 = -1i64;
  v47.m128_u64[1] = 0x3AD429636D08206i64;
  v51 = _mm_xor_ps(v16, v47);                   // Decrypted Raw (unprintable): 02 06 74 16 31 24 20 53 20 44 69 67 69 74 61 6c
  memset(v63, 0, sizeof(v63));
  do
    ++v17;
  while ( v51.m128_i8[v17] );
  sub_FFFFF801BCEF2B2C(v63, &v51);
  v51.m128_u64[0] = 0x3C5A8F9432649Di64;
  v47.m128_u64[0] = 0x431C34EEF05C05D5i64;
  v18 = -1i64;
  v51.m128_u64[1] = 0x3AD429636D08206i64;
  v47.m128_u64[1] = 0x64C32DD516A9F66Fi64;
  v19 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v47), v51);
  v48.m128_u64[0] = 0x315582C14E3D46BBi64;
  v48.m128_u64[1] = 0x77410FCC6170ABCAi64;
  v20 = (__m128)_mm_load_si128((const __m128i *)&v48);
  v49.m128_u64[0] = 0x4AC1249BE823DE60i64;
  v49.m128_u64[1] = 0x5DC27D2DFBEB5206i64;
  v50.m128_u64[0] = 0x21789A509F80B113i64;
  v50.m128_u64[1] = 0x8BBE4558BC680C79ui64;
  v53.m128_u64[0] = 0x23A060BBC844B001i64;
  v53.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
  v54.m128_u64[0] = 0x4C0CE831EFE5F533i64;
  v47 = v19;                                    // Decrypted UTF-8: Handan C
  v21 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v49), v53);
  v54.m128_u64[1] = 0x8BBE4558BC1C621Cui64;
  v52.m128_u64[0] = 0x4526EB856E5427CFi64;
  v52.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v48 = _mm_xor_ps(v20, v52);                   // Decrypted UTF-8: tai Dist
  v50 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v50), v54);// Decrypted UTF-8:  Department
  v49 = v21;                                    // Decrypted UTF-8: ang  Daily Goods
  memset(v64, 0, sizeof(v64));
  do
    ++v18;
  while ( v47.m128_i8[v18] );
  sub_FFFFF801BCEF2B2C(v64, &v47);
  v51.m128_u64[0] = 0x3C5A8F9432649Di64;
  v47.m128_u64[0] = 0x205B34E6FE5C05D3i64;
  v22 = -1i64;
  v51.m128_u64[1] = 0x3AD429636D08206i64;
  v47.m128_u64[1] = 0x23C223FF4EB9EA5Ci64;
  v23 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v47), v51);
  v48.m128_u64[0] = 0x314786F701324986i64;
  v48.m128_u64[1] = 0x544B26B8357DADD1i64;
  v24 = (__m128)_mm_load_si128((const __m128i *)&v48);
  v49.m128_u64[0] = 0x608019DCA728DF6Fi64;
  v49.m128_u64[1] = 0x2EA67636F0E70505i64;
  v53.m128_u64[0] = 0x23A060BBC844B001i64;
  v47 = v23;                                    // Decrypted UTF-8: Nanjing ity Cong
  v25 = (__m128)_mm_load_si128((const __m128i *)&v49);
  v53.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
  v52.m128_u64[0] = 0x4526EB856E5427CFi64;
  v52.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v49 = _mm_xor_ps(v25, v53);                   // Decrypted UTF-8: nology Cly Goods
  v48 = _mm_xor_ps(v24, v52);                   // Decrypted UTF-8: Informatrict LiK
  memset(v65, 0, sizeof(v65));
  do
    ++v22;
  while ( v47.m128_i8[v22] );
  sub_FFFFF801BCEF2B2C(v65, &v47);
  v51.m128_u64[0] = 0x3C5A8F9432649Di64;
  v47.m128_u64[0] = 0x591C3DE1FD4311DBi64;
  v51.m128_u64[1] = 0x3AD429636D08206i64;
  v47.m128_u64[1] = 0x66E362F857A4EC73i64;
  v26 = -1i64;
  v27 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v47), v51);
  v48.m128_u64[0] = 0x2072CBEE1C3B50BBi64;
  v48.m128_u64[1] = 0x70046D835633AADBi64;
  v28 = (__m128)_mm_load_si128((const __m128i *)&v48);
  v49.m128_u64[0] = 0x23A060BBC86AD475i64;
  v49.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
  v47 = v27;                                    // Decrypted UTF-8: Fuqing YZhixiao 
  v29 = (__m128)_mm_load_si128((const __m128i *)&v49);
  v53.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
  v52.m128_u64[0] = 0x4526EB856E5427CFi64;
  v52.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v53.m128_u64[0] = 0x23A060BBC844B001i64;
  v49 = _mm_xor_ps(v29, v53);                   // Decrypted Raw (unprintable): 74 64 2e 00 00 00 00 00 6f 2e 2c 4c 74 64 00 00
  v48 = _mm_xor_ps(v28, v52);                   // Decrypted UTF-8: twork Teion Tech
  memset(v66, 0, sizeof(v66));
  do
    ++v26;
  while ( v47.m128_i8[v26] );
  sub_FFFFF801BCEF2B2C(v66, &v47);
  v48.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v47.m128_u64[0] = 0x205233E2FB4001D7i64;
  v30 = -1i64;
  v51.m128_u64[0] = 0x3C5A8F9432649Di64;
  v47.m128_u64[1] = 0x6ADF07B64FB4ED45i64;
  v31 = (__m128)_mm_load_si128((const __m128i *)&v47);
  v48.m128_u64[0] = 0x4526EB856E5427ACi64;
  v32 = (__m128)_mm_load_si128((const __m128i *)&v48);
  v51.m128_u64[1] = 0x3AD429636D08206i64;
  v52.m128_u64[0] = 0x4526EB856E5427CFi64;
  v52.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v48 = _mm_xor_ps(v32, v52);                   // Decrypted UTF-8: c
  v47 = _mm_xor_ps(v31, v51);                   // Decrypted UTF-8: Jeromin untan Ne
  memset(v67, 0, sizeof(v67));
  do
    ++v30;
  while ( v47.m128_i8[v30] );
  sub_FFFFF801BCEF2B2C(v67, &v47);
  v47.m128_u64[0] = 0x3C5A8F9432649Di64;
  v51.m128_u64[0] = 0x6B5309AFFD590DD3i64;
  v47.m128_u64[1] = 0x3AD429636D08206i64;
  v51.m128_u64[1] = 0x3AD429640BFEE69i64;
  v33 = -1i64;
  v51 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v51), v47);// Decrypted UTF-8: Niki SokCody Eri
  memset(v68, 0, sizeof(v68));
  do
    ++v33;
  while ( v51.m128_i8[v33] );
  sub_FFFFF801BCEF2B2C(v68, &v51);
  v51.m128_u64[0] = 0x3C5A8F9432649Di64;
  v47.m128_u64[0] = 0x205B34E6FE5B01DFi64;
  v51.m128_u64[1] = 0x3AD429636D08206i64;
  v47.m128_u64[1] = 0x66DD2DDE58B9ED4Ci64;
  v34 = _mm_xor_ps((__m128)_mm_load_si128((const __m128i *)&v47), v51);
  v48.m128_u64[0] = 0x11068EE20F396EEFi64;
  v48.m128_u64[1] = 0x5B472F837B7BA1DDi64;
  v35 = (__m128)_mm_load_si128((const __m128i *)&v48);
  v49.m128_u64[0] = 0x23A04EDFBC089078i64;
  v49.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
  v47 = v34;                                    // Decrypted UTF-8: Beijing olov
  v36 = (__m128)_mm_load_si128((const __m128i *)&v49);
  v53.m128_u64[1] = 0x2EA61242BCCB2B6Ai64;
  v52.m128_u64[0] = 0x4526EB856E5427CFi64;
  v52.m128_u64[1] = 0x3C2843EC1513C2B8i64;
  v53.m128_u64[0] = 0x23A060BBC844B001i64;
  v49 = _mm_xor_ps(v36, v53);                   // Decrypted UTF-8: y Ltd.
  v48 = _mm_xor_ps(v35, v52);                   // Decrypted UTF-8:  Image T
  memset(v69, 0, sizeof(v69));
  do
    ++v1;
  while ( v47.m128_i8[v1] );
  sub_FFFFF801BCEF2B2C(v69, &v47);
  v48.m128_u64[0] = 0i64;
  v71 = v70;
  v72 = v55;
  v47 = 0i64;
  sub_FFFFF801BCEF2EC4(&v47, 15i64, &v72, &v71);
  v37 = 15i64;
  v38 = (__int64 *)v70;
  v39 = 1;
  do
  {
    v38 -= 4;
    --v37;
    v40 = v38[3];
    if ( v40 > 15 )
    {
      v41 = *v38;
      if ( v40 + 1 >= 0x1000 )
      {
        v42 = *(_QWORD *)(v41 - 8);
        v43 = (const char *)(v41 - v42);
        if ( (unsigned __int64)(v43 - 8) > 0x1F )
        {
          Xlength_error(v43);
          JUMPOUT(0xFFFFF801BCEF3E7Eui64);
        }
        v41 = v42;
      }
      operator_delete(v41);
    }
    v38[2] = 0i64;
    v38[3] = 15i64;
    *(_BYTE *)v38 = 0;
  }
  while ( v37 );
  if ( subjectName && *subjectName )
  {
    for ( i = v47.m128_u64[0]; i != v47.m128_u64[1]; i += 32i64 )// range based loop for vector possibly
    {
      v45 = (char *)i;
      if ( *(_QWORD *)(i + 24) > 15ui64 )
        v45 = *(char **)i;
      if ( stristr(subjectName, v45) )
        goto LABEL_48;
    }
  }
  else
  {
    v39 = 0;
LABEL_48:
    v4 = v39;
  }
  sub_FFFFF801BCEF4A08(&v47);
  return v4;
}
```

`EmacVerifyFileUnknown` is virtualized so i have no idea what's being verified there.

# IDA decompiled snippets

[Callbacks Snippets](https://github.com/crvvdev/emaclab-reversal/blob/main/cb.c)

# Conclusion

Very solid approaches, minifilter with signature verification on kernel is the today standard.
Weak points surely are the global variables, anyone can manipulate the game process id, as well as the variables storing addresses from ntdll, kernel32, etc.