---
title: 'Challenge: Poison null bytes'
disqus: hackmd
---

# Overall

- It seems similar to [Poison null bytes](/house_of_einherjar/README.md) (The House of Einherjar). However, in this technique, I **overwrite the least significant byte of the free chunk** instead of allocated chunk.

# Approach
- Thus, ***the size field of the free chunk decrease***(0x210 -> 0x200 -> decrease 0x10 bytes). It leads to the ***prev_size and prev_inuse flags of succeeding chunk not be updated correctly***(0x10 bytes before the right location).   
- When I free the chunk after vitic chunk, and find the way to trigger consolidate, I can overlap(free) the allocated chunk -> trigger somethings to leak libc + heap
- The challenge binary ***won't let us make arbitrarily large requests***, overwriting the malloc hook with the address of a one-gadget seemed like a sensible approach. However, ***satisfying any of the one-gadget constraints in this scenario proves difficult***. 
- At this point, you may have ***considered file stream exploitation instead*** and props to you if you tried. Unfortunately, the version of GLIBC we're working with, 2.25, implements ***a mitigation against file stream exploitation***. 
    - ***It can be bypassed somewhat trivially by writing any nonzero value into the dlopen hook, perhaps via an unsortedbin attack.***

One to disable libio vtable protection and one to trigger a House of Orange attack is one unsortedbin attack too many. So the fastbin dup failed us, as did the unsortedbin attack, but what if I ***combined them***?
- The fastbin dup technique relies upon the presence of a fake chunk size field. In the case of the fake chunk overlapping the malloc hook, this is supplied by a pointer to a library address which consistently starts with the value 0x7f and is followed by a null padding quadword. I've so far been ***unable to target things like the free hook with a fastbin dup because there aren't any pre-existing fake chunk size fields close enough to it.***
- However an unsortedbin attack could be used to provide one. Remember that the ***unsortedbin attack writes the address of an arena's unsortedbin to a location of our choosing***. Since arenas, both main and otherwise, will typically be ***mapped at 0x00007f addresses***, if we point an unsortedbin attack at the memory before the free hook, it will write a viable fake size field there.


# Further use
- It doesn't require heap + libc leak.
- It can trigger some mitigations. 
# Script

[***shell.py***](./shell.py)
