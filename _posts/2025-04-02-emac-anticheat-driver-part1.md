---
title: "EMACLAB Anticheat Driver, Part 1: Import Table"
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

# First things first

The first i did was jump into a VM and try dump the driver file from memory, which really was not needed, since, around some time ago [Microsoft Windows Hardware Compatibility Lab](https://learn.microsoft.com/en-us/windows-hardware/design/compatibility/) has stopped signing drivers that use imports/memory/resources protection and/or are packed, meaning it's only possible to use virtualization capabilities from PE protectors, which in their case is [VMProtect](https://vmpsoft.com/) 3.8+.

# Jumping into analysis

By looking at the file import table i certainly knew that they must have their own import table, that's today's standards for any security software, specially for anticheats. 

_lets check out the file import table real quick..._
![img](/assets/img/emac-anticheat-driver-part1/iat.png)

It's very obvious that a product like this has way more imports than those...

---

Also with my experience i easily spotted some common patterns oftenly used to "xor" strings, more specifically and famously  [JustasMasiulis/xorstr](https://github.com/JustasMasiulis/xorstr). This library is used to obfuscate strings in a static analysis point-of-view, but luckily there's known scripts that will (hopefully) help me out to statically decrypt those without a hassle. And that's what i did, using scripts i was able to read strings in plain state which helped me to understand what's going on.

_cheeky string obfuscation completely owned by the power of python scripting_
![img](/assets/img/emac-anticheat-driver-part1/xorstr.png)

_now it's easy, just hit F5 and figure it out what's going..._
![img](/assets/img/emac-anticheat-driver-part1/iat-2.png)

As seen in the image above, it's clear that a global variable is being initialized here, in that case a pointer to an exported system routine. There's way more pointers being initialized in this single function, so i have renamed it to `InitializeImportTable`.

## Well, it surely can't be that simple, right!?

If you're experienced enough you might already know that there's no way it can be that simple, mainly because if there's no other protection measures it means that someone can simply modify the global pointer to something else like a hook and intercept the call, that's very concerning since the anticheat can really be bypassed at this point.

That is the case, you can modify it, but you have to figure it out how in the first place, so let's do it!

First i found the pointer to a highly used API, __ExAllocatePoolWithTag__, then by looking at the XREFs i could find where the call is actually constructed, take a look:

_a lot of calls, surely we can reverse engineer and figure out how it's being called_
![img](/assets/img/emac-anticheat-driver-part1/xrefs.png)

_IDA pseudo-code of declaration and usage_
```
ExAllocatePoolWithTagFn = (__int64 (__fastcall *)(_QWORD, __int64, _QWORD))(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) & -(__int64)(((unsigned __int64)ExAllocatePoolWithTag ^ qword_FFFFF801BCFACC40) > qword_FFFFF801BCFACC38));

if ( !ExAllocatePoolWithTagFn((unsigned int)g_EmacPoolType, 0x58i64, 'CAME') )
{
    ...
}
```

Honestly i was expecting more, but that's good enought to make people confused. Let me explain it to you:

- `qword_FFFFF801BCFACC40` -> Constant used to xor import table pointers
- `ExAllocatePoolWithTag` -> The actual pointer
- `qword_FFFFF801BCFACC38` -> Will generate opaque predicates, meaning the other constants and maths are just garbage to try make static analysis harder.

How do i know that? Simply because when analyzing what i call `EmacFindExportByName` i have noticed that only `qword_FFFFF801BCFACC40` really matters as it's used to xor the resulting address, a failed attempt to obfuscate/protect the import table pointers.

![img](/assets/img/emac-anticheat-driver-part1/lmao_obfs.png)

So basically: 

- `<IAT pointer> ^ qword_FFFFF801BCFACC40` = Returns IAT real address
- `<IAT pointer> = <New pointer> ^ qword_FFFFF801BCFACC40` = Modify IAT address to new address

![img](/assets/img/emac-anticheat-driver-part1/emaclab.gif)

Honestly, this left me wondering what's the benefit of doing such a thing!? Clearly there's no real protection, not even throught obscurity, you're only using more stack space... and stack space is something to be considered in kernel driver development (see [Using the kernel stack](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-the-kernel-stack))

# Oopsie Daisy

When analysing the driver i have noticed the huge amount of times where stack is allocated (i will probably get into that subject again in this series).

MSDN says kernel-mode stack is limited to approximately three pages, we know that a page has 4096 bytes on Windows, meaning that, in theory, allocating more than 12288 bytes is dangerous. Their import table initialization routine that i have called `InitializeImportTable` allocates 13664 bytes of stack memory ![img](/assets/img/emac-anticheat-driver-part1/eek2.gif)

_this is literally a bomb that can explode or not_
![img](/assets/img/emac-anticheat-driver-part1/huge_stack.png)

This is mainly due to the junk code from import obfuscation and jm-xorstr. If you're an EMACLAB employee, i beg you to read [Kernel-Mode Driver Architecture Design Guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/).

# IDA decompiled snippets

The way they obtain import addresses is very simple, just parsing the PE headers and walking export table. They directly search for the module info in __PsLoadedModuleList__.

[IAT Snippets](https://github.com/crvvdev/emaclab-reversal/blob/main/iat.c)

# Conclusion

That's it for imports, there's nothing special there, nothing that has not be seen or done before.