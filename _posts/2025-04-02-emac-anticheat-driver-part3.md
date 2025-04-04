---
title: "EMACLAB Anticheat Driver, Part 3: Anti-virtualization"
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

# Hypervisor checks

One interesting part about the anticheat is the hypervisor checks, but as far as i could find there's nothing out of ordinary.

Most of those checks are straight taken from other anticheats, or have been talked about in game cheating forums.

_Those checks focus on exploiting bad hypervisors_
![img](/assets/img/emac-anticheat-driver-part3/hv_2.png)

![img](/assets/img/emac-anticheat-driver-part3/hv_3.png)

_Messing with LBR virtualization_
![img](/assets/img/emac-anticheat-driver-part3/hv_4.png)

![img](/assets/img/emac-anticheat-driver-part3/hv_1.png)


_KiErrata1337Present, KiErrataSkx55Present, KiErrata704Present_
![img](/assets/img/emac-anticheat-driver-part3/hv_5.png)

_Checks if CPUID hypervisor is Microsoft Hyper-V_
![img](/assets/img/emac-anticheat-driver-part3/hv_6.png)

_Checks if CPUID processor name is Intel as proceeding checks are only available for Intel CPUs_
![img](/assets/img/emac-anticheat-driver-part3/hv_7.png)

_Then verifies if VMX extensions are enabled, perform calls to try detect hypervisors using SEH_
![img](/assets/img/emac-anticheat-driver-part3/hv_8.png)

![img](/assets/img/emac-anticheat-driver-part3/hv_9.png)

_CPU timing checks to try detect virtualization_
![img](/assets/img/emac-anticheat-driver-part3/hv_10.png)

---

There's this one interesting piece of code, i named it `EmacGetPciLatency`. I am not a expert in DMA/PCI cheats, to be honest i am very bad when it codes to the hardware part of computers, but my main guess is that those checks are specifically for PCI device detection somehow, but i can be completely wrong.

```cpp
unsigned __int64 __fastcall EmacGetPciLatency(unsigned int a1, unsigned __int8 a2, char a3, char a4, char a5)
{
  unsigned __int64 v5; // rsi
  unsigned __int64 v9; // rbx
  int v10; // eax
  __int64 v11; // r15
  unsigned int v12; // edi
  unsigned __int64 v13; // r14
  int v14; // edi
  unsigned __int8 CurrentIrql; // bl
  unsigned int v17; // [rsp+20h] [rbp-10h] BYREF
  unsigned int v18; // [rsp+24h] [rbp-Ch] BYREF
  unsigned int v19; // [rsp+28h] [rbp-8h] BYREF
  unsigned int v20; // [rsp+50h] [rbp+20h] BYREF

  v5 = 0i64;
  v18 = 0;
  v20 = 0;
  v19 = 0;
  v17 = 0;
  v9 = a1;
  KeGetCurrentIrql();
  EmacGetTscTop(&v18, &v19);
  EmacGetTscBottom(&v20, &v17);
  EmacGetTscTop(&v18, &v19);
  EmacGetTscBottom(&v20, &v17);
  if ( (_DWORD)v9 )
  {
    v10 = a3 & 0x1F;
    v11 = (unsigned int)v9;
    v12 = a4 & 7 | (8 * (v10 | (32 * (a2 | 0xFFFF8000))));
    v13 = (unsigned int)v9;
    v14 = a5 & 0xFC | (v12 << 8);
    do
    {
      CurrentIrql = KeRaiseIrql(2u);
      EmacGetTscTop(&v18, &v19);
      __outdword(0xCF8u, v14);
      __indword(0xCFCu);
      EmacGetTscBottom(&v20, &v17);
      KeRaiseIrql(CurrentIrql);
      v5 += (v17 | ((unsigned __int64)v20 << 32)) - (v19 | ((unsigned __int64)v18 << 32));
      --v11;
    }
    while ( v11 );
  }
  else
  {
    v13 = v9;
  }
  return v5 / v13;
}
```

# IDA decompiled snippets

[Hypervisor Checks Snippets](https://github.com/crvvdev/emaclab-reversal/blob/main/hv.c)

# Conclusion

I was able to run the anti-cheat on virtualized environments like VMware and KVM, as long as i had Hyper-V running i had no problems, but that doesn't necessarely means there's was no flags. If you wanna play safely my guess is: use KVM with QEMU patches and enable Hyper-V, this should be enought for ban evasion, or, if you're the ultimate linux user that should work for you.

Like i said those checks are nothing new, most modern anti-cheats like Riot Games Vanguard take this more seriously and have better, advanced checks to detect virtualization.

