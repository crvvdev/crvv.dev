---
title: "EMACLAB Anticheat Driver, Part 2: Globals"
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

# Globals

There are a few interesting "globals" which can lead to some assumptions, for example:

![img](/assets/img/emac-anticheat-driver-part2/find.png)

Some are pretty straightforward, like finding syscall indexes dynamically, getting module information from PEB, addresses for tables/dispatchers often used for integrity check, offsets for dynamic system structs and the list goes.

Let's take `FindNtPsLoadedModuleResource` as an example:

_tries to obtain address by export_
![img](/assets/img/emac-anticheat-driver-part2/loaded_1.png)

_fallback to famous 'FindPattern' search_
![img](/assets/img/emac-anticheat-driver-part2/loaded_2.png)

# Why i don't like dynamic search 

The main thing that leads me to confusion is why the fuck there's dynamic search for these symbols; like i said it's a symbol so i wonder why not simply obtain symbol's and parse its information!? There's nothing wrong with using __FindPattern__ ~~i guess~~, but me personally would rather parse symbols, specially because this is a demand driver so obtaining addresses in the driver logic itself is not necessary.

They even take it as far as using a disassembly engine, creating a smart logic to obtain offsets dynamically.

_They're using [bitdefender/bddisasm](https://github.com/bitdefender/bddisasm)_
![img](/assets/img/emac-anticheat-driver-part2/kdpdebug.png)

### Extra

For some reason they have checks for ancient Windows versions like 7, 8 and 8.1. This leave me wondering why this code is still left here, Windows 7 for example is not actively supported on Steam for quite a while, and i am pretty sure Windows 10 is the minimum OS required for Counter-Strike: 2. This is honestly dead code, since it will never be actually used/ran.

![img](/assets/img/emac-anticheat-driver-part2/win7.png)

# Assumptions

Some of those globals are self-explanatory, for example `FindNtWmipSMBiosTableLength` surely will be used to extract information about SMBIOS, `FindWin32kbase_gDxgkInterface` this will get the `gDxgkInterface` table and will perform integrity check later, `FindNtKdpDebugRoutineSelect` and `FindNtKdpTrap[2,3]` will be used to verify global exception hooks, `FindNtPiDDBCacheTable` and `FindNtMmUnloadedDrivers` are both very known tables that contain information about unloaded drivers ultimately leading to traces if not cleaned correctly, and the list goes...

# IDA decompiled snippets

[Globals Snippets](https://github.com/crvvdev/emaclab-reversal/blob/main/globals.c)

# Conclusion

I decided not go so deep into that subject, if you're curious then take a look at the .IDB