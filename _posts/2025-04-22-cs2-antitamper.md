---
title: "Analzying Counter-Strike: 2 Anti-tamper system"
last_modified_at: 2025-04-22T00:00:00-00:00
categories:
  - anticheat analysis
tags:
  - antitamper
  - cs2
  - counter-strike
  - analysis
---

Counter-Strike: 2 is one of the most played games in the world right now, but it's known for not having a decent anti-cheat system. We will talk about the new measures Valve has taken to try detect and flag cheaters using game internal anti-tampering.

Last year i published my analysis on UnknownCheats [Anti-tamper reversal](https://www.unknowncheats.me/forum/counter-strike-2-a/667890-anti-tamper-reversal.html), it really didn't catched too much attention so i might just get into the topic again on my blog this time.

# What is Anti-tamper?

We can consider anti-tampering a piece of code that try to detect signed/read-only memory tampering but it also can be used to detect unwanted modifications in classes that in a game context can be player state and some other sensitive information that can enable cheats such as wallhacks. That's not really everything anti-tampering means or can do but that's the case for Counter-Strike: 2. 

The game already has some security measures, like only allowing some whitelisted .DLL(s) to be loaded into the game unless the it's booted with `-allow_third_party_software`, as well as checking the engine interfaces pointers and verifying integrity of so called "platform modules" that are registered in a internal list. A very nice breakdown of those measures can be found at [danielkrupinski/cs2-anticheat](https://github.com/danielkrupinski/cs2-anticheat) already so i will not get very deep into those subjects, instead we will talk about something that was not really been talked before.

## How Valve implemented anti-tamper?

The anti-tamper was implemented as a thread-safe function that we will be calling `AntiTamperCheck()`, this function will be often invoked in several places at the game engine, this is done to ensure some values are not modified arbitrary by hackers. All sensitive values are stored in hash table that will then, at the right moment, be checked for unwanted modifications. This function also verifies the caller return address, if the return address is outside a legitimate module then it's flagged as a report. The return address verification is most likely to detect manually mapped modules, a manually mapped module is basically a piece of unsigned code that was loaded manually instead of using Windows loader.

Finally, if flagged, it will send a message to the server. 

<details>
  <summary>Click to show/hide code</summary>
  {% gist d1b040b9873fba0a8cec458ba732643c %}
</details>

## Final regards

This system would be very good and effective, 10/15 years ago. It's VERY easy to bypass all of it by simply patching the memory directly or not letting the flag packet ever reach the server.
