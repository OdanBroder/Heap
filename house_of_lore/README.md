# Overall 
![image](https://hackmd.io/_uploads/SyBPO_KBA.png)


- ***Linking a fake chunk into an unsortedbin*** is equivalent to aiming an ***unsortedbin attack*** at a fake chunk by ***overwriting the unsorted chunk’s bk with the address of the fake chunk***. 
    - **The fake chunk must have a bk which points to a writable address**. 
    - The fake chunk can be allocated directly from the unsortedbin, although its size field must match the request size and differ from the chunk with the corrupt bk. 
- ***Linking a fake chunk into a smallbin*** requires **overwriting the bk of a chunk linked into a smallbin with the address of the fake chunk**  
    - We must ***ensure the victim->bk->fd == victim check passes by writing the address of the victim small chunk into the fake chunk’s fd pointer before the small chunk is allocated***. 
    - Once the small chunk is allocated, the ***fake chunk must pass the victim->bk->fd == victim*** check too, this can be achieved by **pointing both its fd & bk at itself**(not in this challenge). 
    - **In scenarios where the fake chunk cannot be changed after the victim small chunk is allocated**, it’s possible to **use a 2nd fake chunk**, although only 1 quadword is required to hold a fake fd. 
        - ***Pointing this 2nd fake chunk’s fd at the primary fake chunk***, and the primary fake chunk’s bk at the 2nd fake chunk will satisfy the check. The size of the fake chunk is irrelevant as it is not checked. 
- ***The easiest way to link a fake chunk into a largebin*** involves ***overwriting a skip chunk’s fd with the address of a fake chunk and preparing the fake chunk’s fd & bk to satisfy the safe unlinking checks.*** 
    - ***Malloc will not check the skip chunk’s fd for a viable chunk if the skip chunk is the last in the bin.***
        - **The fake chunk must have the same size field as the skip chunk.** 
        - **The skip chunk must have another same-sized or smaller chunk in the same bin**. 
    - The fake chunk’s fd & bk can be prepared to satisfy the safe unlinking checks by pointing them both at the fake chunk.
 
 
 # Approach
- Link a fake chunk into the unsortedbin, smallbins or largebins by tampering with inline malloc metadata. 
 
 # Further use


- The first is that much like allocating fake chunks from the fastbins, I can misalign my fake chunk. If I'm trying to find a naturally occurring size field, I can also use invalid flag combinations, including a set forth-least significant bit.
- The second thing is that because I control the fake chunk's bk I can potentially point it at another fake chunk, then allocate that.
 
 # Limitations

- The amount and precise location of controlled memory ***required to construct fake small and large chunks for the*** House of Lore can make it difficult to implement against these bins. 
-  It requires you must explore ***UAF(write-after-free)***.

 # Note
 The fake chunk must satisfy 2 constraints
 - The first is that its size field has to pass the unsortedbin size sanity check, meaning it should take a value between the minimum valid chunk size and the total amount of memory the current thread's arena has checked out from the kernel, a value held in the arena's "system_mem" field.
 - The second constraint is that the fake chunk's backward pointer must hold the address of writable memory since it will be referenced and used in a write operation during the partial unlink.
