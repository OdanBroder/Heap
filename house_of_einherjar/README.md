# The House of Einherjar

## Overall 
![image](https://hackmd.io/_uploads/Skq2dxcrR.png)


- The House of Einherjar was originally presented as a ***single null-byte overflow technique***, but this is not its most realistic application. It assumes an overflow that can ***clear a victim chunk’s prev_inuse bit*** whilst having control of the victim chunk’s prev_size field. 
- The victim’s ***prev_size field*** is populated such that ***when the victim chunk is freed it consolidates backwards with a fake chunk on the heap or elsewhere***. In this case, arbitrary allocations can be made from the fake chunk which could be used to read from or write to sensitive data. 


## Approach
- Clear a chunk’s prev_inuse bit and consolidate it backwards with a fake chunk or an existing free chunk, creating overlapping chunks. 
## Further use

- It is also possible to consolidate with legitimate free chunks on the heap, creating overlapping chunks which can be used to build a stronger primitive.
- The House of Force, GLIBC versions, 2.28 and below don't have any top chunk size integrity checks, so it's preferable to do things the way we have here by consolidating with the top chunk, unless you're able to modify your fake chunk's size field between consolidation and allocation.
- Not only does this method not require a heap leak, since the distance between chunks on the same heap is both relative and deterministic, but legitimate free chunks will inherently pass this safe unlinking checks.


## Limitations

- ***The size vs prev_size check introduced in GLIBC version 2.26*** requires a designer to ***set an appropriate size field in their fake chunk.***
- The second more robust size vs. prev_size check was introduced in ***GLIBC version 2.29*** which requires the fake chunk's size field to actually match the freed chunk's prev_size field.

## Note
In the Safe Unlink technique, I set our counterfeit prev_size field to a value that allowed mallocto find a fake chunk we'd prepared in chunk A's user data, then unlink it in preparation for consolidation. I'm going to do the same thing here for the House of Einherjar, with two small differences.
- The first difference is that our fake chunk won't reside on the heap. Instead, I'll craft it in this program's data section, overlapping the target data.
- The second is that I'm uninterested in leveraging the unlinking process, we don't know the address of any pointers to chunks because unlike the safe_unlink binary, this program keeps its chunk pointers on the stack, which we haven't leaked.
Once we enable ASLR and the distance between the heap and program's data section greatly increases, this can result in a very large fake chunk getting linked into the unsortedbin, which will subsequently fail the size integrity check when we try to allocate it.

## Sanity checks
- It's attempting to ***compare the size field of the chunk being unlinked with the prev_size field that led it to that chunk***. Of course, those two values should match, and this check was introduced specifically as an attempt to combat exploitation of single null byte overflows. Fortunately for us, there are a couple of ways in which we could pass this check.
    - ***The first is simply to set our fake chunk's size field to match that of our bogus prev_size field.*** However, the house of einherjar binary only leaks its heap start address after we've already input our username, which contains our fake chunk metadata, and we're unable to go back and edit it.
    - There is a second way in which we could pass the size and prev_size check, the flaw in this implementation of the size vs prev_size check is that it operates entirely from within the context of the chunk being unlinked, known as the "victim" chunk. It has no idea where the prev_size field that led it to that chunk resides.
        - This means that it has to rely on the size field of the victim chunk in order to locate the prev_size field with which to compare it.
        - This can lead to a disconnect between the prev_size field the macro intends to find and the prev_size field it actually finds.
        - Let's consider what's happening when our fake chunk undergoes this check.
        - The size of the chunk is determined by the chunksize() macro, which simply checks the second quadword at the address it's passed. The result is accurate and in this case, yields 0x31. This value is compared against a prev_size field, which is found as follows:
            - The next_chunk() macro attempts to find the succeeding chunk by adding the victim chunk's size to its address, here 0x602010 one plus 0x30 yields 0x602040, which is not the address of chunk B, rather this random patch of memory in the program's data section.
            - Next, the prev_size() macro simply returns the value at that location. The result is that instead of comparing our fake chunk's size filled with chunk B's prev_size field. It's compared against memory at an offset from our fake chunk that I control.
        - Sadly, in this case, I can't influence any memory after our fake chunk in which to provide another bogus size field, but I don't actually need to. There is one value we can choose for our fake chunk's size that will always pass the size and prev_size check. **That value is 8.**
            

