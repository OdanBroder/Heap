# Safe unlink
## Overall
The Safe Unlink technique is similar to the Unsafe Unlink, but accounts for safe unlinking checks introduced in GLIBC version 2.3.4. ***The safe unlinking checks ensure that a chunk is part of a doubly linked list before unlinking it.*** 
    - The checks **PASS** if the ***bk of the chunk pointed to by the victim chunk’s fd points back to the victim chunk***, and the ***fd of the chunk pointed to by the victim’s bk also points back to the victim chunk.*** 
- Forge a fake chunk starting at the first quadword of a legitimate chunk’s user data, ***point its fd & bk 0x18 and 0x10 bytes respectively before a user data pointer to the chunk in which they reside***. Craft a prev_size field for the succeeding chunk that is 0x10 bytes less than the actual size of the previous chunk. Leverage an ***overflow bug to clear the succeeding chunk’s prev_inuse bit***, when this chunk is freed malloc will attempt to ***consolidate it backwards with the fake chunk***. 

- ***The bk of the chunk pointed to by the fake chunk’s fd points back to the fake chunk***, and ***the fd of the chunk pointed to by the fake chunk’s bk also points back to the fake chunk***, satisfying the safe unlinking checks. 
- The **RESULT** of the unlinking process is that the ***pointer to the fake chunk (a pointer to a legitimate chunk’s user data) is overwritten with the address of itself minus 0x18.***

**If this pointer is used to write data, it may be used to overwrite itself a second time with the address of sensitive data, then be used to tamper with that data.**



## Approach

- The modern equivalent of the Unsafe Unlink technique. Force the unlink macro to process designercontrolled fd/bk pointers, leading to a reflected write. The safe unlinking checks are satisfied by aiming the reflected write at a pointer to an in-use chunk. Program functionality may then be used to overwrite this pointer again, which may in turn be used to read from or write to an arbitrary address. 

## Further use 

By forging a very large prev_size field the consolidation attempt may wrap around the VA space and operate on a fake chunk within the freed chunk. 


## Limitations 

A size vs prev_size check introduced in GLIBC version 2.26 requires the fake chunk’s size field to pass 
a simple check; the value at the fake chunk + size field must equal the size field, setting the fake size 
field to 8 will always pass this check. A 2nd size vs prev_size check introduced in GLIBC version 2.29 
requires the fake chunk’s size field to match the forged prev_size field.
