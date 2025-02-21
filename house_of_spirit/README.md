# Overall

- The House of Spirit is the only technique that ***does not rely on one of the conventional heap-related bugs***, instead it takes advantage of a scenario that allows a designer to ***corrupt a pointer that is subsequently passed to free()***.

- By passing a ***pointer to a fake chunk to free()***, the ***fake chunk can be allocated and used to overwrite sensitive data***. 
    - The fake chunk must have an ***appropriate size field*** and in the case of a **FAST CHUNK**, must have a ***succeeding size field that satisfies size sanity checks***, meaning that a designer ***must control at least 2 quadwords that straddle the target data.*** 

- In the case of a small chunk, there must be 2 trailing size fields to ensure forward consolidation is not attempted, fencepost chunks will work. Because of this a designer must control at least 3 quadwords that straddle the target data.

# Approach 

- Pass an arbitrary pointer to the ***free()*** function, ***linking a fake chunk into a bin which can be allocated later***. 

# Further use
When ***combined with a heap leak***, the House of Spirit can be used to ***coerce a double-free which can provide a more powerful primitive.*** 

# Limitations
- If an arena’s contiguity flag is set, fake small chunks must reside at a lower address than their thread’s heap, this does not apply to fake fast chunks. Fake chunks must pass an alignment check, which not only ensures that they are 16-byte aligned but mitigates the presence of a set 4th-leastsignificant bit in the size field. 
- Fake chunks must avoid having set NON_MAIN_ARENA and IS_MMAPED bits, in the former case the free() function will search for a non-existent arena and will most likely segfault whilst doing so, and in the latter case the fake chunk is unmapped rather than freed. 

# Sanity checks
**Size field**: IS_MMMAPED, NON_MAIN_ARENA and fourth-least significant bit must be clear.
- **IS_MMAPED**
    - When ***malloc receives a request larger than a variable named "mmap_threshold"***, the request will be serviced via the GLIBC mmap() function rather than from an arena. More deatail about mmap can be search from its manpage and you can find the "mmap_threshold" variable amongst the malloc parameters, which can be dumped with pwndbg `mp` command
    - When a chunk is allocated via mmap, its IS_MMAPPED flag is set. ***When the free() function operates on a chunk with a set IS_MMAPPED flag,instead of linking it back into an arena, it will unmap the chunk with GLIBC's munmap() function.*** 

- **NON_MAIN_ARENA**
    - There are **two types of arenas**, the *main arena*, which resides in GLIBC's data section and *non-main arenas*, which can be created by malloc in multithreaded applications.
    - Because ***non-main arenas are created dynamically at runtime***, **malloc can't resolve them using symbols**. Instead, it gives new arenas and their corresponding heaps something called a "heap_info" struct and ensures they're mapped at a specific alignment. ***Malloc can then locate non-main arenas by applying an and-mask to a chunk's address to find its corresponding heap_info struct.*** To determine which arena a chunk should be linked into, the free() function checks its NON_MAIN_ARENA flag.
    - When free() comes across a set NON_MAIN_ARENA flag, ***rather than linking the chunk into the main arena, it will instead apply that and-mask to the chunk's address***, ***in effect rounding it down to a much lower value in an attempt to locate that chunk's arena***. Of course, our fake chunk doesn't belong to an arena, and therefore, when we try to free it, ***malloc rounds its address down to an unmapped address and subsequently segfaults***. Under some circumstances, you could use the NON_MAIN_ARENA flag to orchestrate mayhem by providing a fake arena.
    
***malloc's size sanity checks***: instead of operating on the chunk being freed, it's testing the succeeding chunk.
- If that chunk is **smaller than a fencepost chunk or larger than av->system_mem**, the mitigation is triggered.
 
**Constraints for chunk with size larger than fastbin size:** "normal" chunk size range, making it eligible for unsortedbin insertion on free.
- **prev_inuse bit must to be set**:  clear prev_inuse flag on a non-fast chunk will cause malloc to consolidate it with the previous chunk.
- ***prev_inuse bit of size field of the succeeding chunk must be set.*** If that flag is clear, that chunk we're trying to free must already be free.
- The Unsafe Unlink technique taught us that malloc will also check the prev_inuse flag of the chunk after the succeeding chunk. If that's clear, then it will attempt forward consolidation. The easiest way to avoid this is to provide a third fake size field using fencepost chunks(0x11).
- The version of GLIBC this binary is linked against, 2.30, also performs the same next size sanity check during unsortedbin scanning.

# Note

- These course binaries keep track of their allocated chunks using an array named "m_array" and the house_of_spirit program keeps its m_array on the stack.
- This binary has an overflow bug which allowed us to overwrite a pointer that was subsequently passed to the free() function. The overflow bug manifests on the stack, but it could have occurred anywhere. We used this bug to replace a pointer with the address of a fake chunk we'd prepared overlapping ourtarget data.
- Using a fake normal chunk in the House of Spirit has the same constraints as using a fast chunk, plus we need to control or find a third quadword with a set least-significant bit.
- The advantages of using a normal chunk are that it can take on a wider range of sizes and we can remainder it, meaning that we don't have to request the exact size of our fake chunk to allocate from it.
- There is one disadvantage to using normal chunks in the House of Spirit
    - Checking whether the next chunk is beyond the boundaries of the arena, this check is only applied to normal chunks during the free process, fast chunks are exempt.
    - Our fake normal chunk, along with its succeeding chunk, are nowhere near the boundaries of the heap, but it's only checking whether the next chunk is at an address larger than or equal to that of the end of the top chunk.
    - This means that any address below that is fair game, including the writable segment of the program.

- So if you're using fake fast chunks in the House of Spirit, they can be located anywhere you like, but when using fake normal chunks you're limited to addresses below the end of the main arena's heap. The exception to this rule is if the main arena has become non-contiguous under memory pressure.

# Drop a shell
***It requires more contrains***
- The first approach that comes to mind is why not just free that 0x7f chunk that we used for our fastbin dup the one that sits just before the malloc hook and is consistently formed by one of the standard IO vtable pointers and following padding quadword.
    - That won't work because a 0x7f size field has three set bits that will cause our House of Spirit primitive to fail, namely the IS_MMAPPED bit, the NON_MAIN_ARENA bit and the fourth-least significant bit.
- However, it triggered a mitigation before the one that checks the freed chunk's size field. This mitigation is checking two things;
    - The first is whether the freed chunk wraps around the VA space House of Force style.
    - The second is whether the chunk is 16 byte aligned, due to the nature of how heaps are mapped and the fact that chunk sizes are always multiples of 16 bytes on this architecture, legitimate chunks should never be misaligned.

***Constraints***
- I target to one of malloc's hooks, our fake junk must be in the fastbin range because ***normal chunks can't be freed at addresses above the default heap***.
- The second, third and fourth least significant bits of our fake chunks size field must be clear.
- Our fake chunk must be 16 byte aligned.
- I need to provide a succeeding size field of appropriate value at the right location.
