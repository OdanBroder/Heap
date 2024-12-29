# Unsafe-Unlink Exploit Overview

This document details the **Unsafe-Unlink** technique, a heap exploitation strategy targeting older versions of glibc (<= 2.3.3). The attack manipulates heap metadata during chunk consolidation, leveraging the unlink macro for arbitrary memory writes. 

---

## **Mechanism**

### Chunk Consolidation and Unlinking
- During ***chunk consolidation***, a chunk already ***linked into a free list*** is unlinked via the `unlink` macro.
- The unlinking process involves a **reflected write** using the chunk's **forward (`fd`)** and **backward (`bk`)** pointers:
  1. The victim's `bk` pointer overwrites the `bk` of the chunk pointed to by the victim's `fd`.
  2. The victim's `fd` pointer overwrites the `fd` of the chunk pointed to by the victim's `bk`.
- If a chunk with designer-controlled `fd` and `bk` pointers is unlinked, this reflected write can be exploited.

### Exploitation Workflow
#### Steps:
1. **Overflow to Modify Chunk Metadata**:
   - Overflow into a chunk's **size field** to clear its `prev_inuse` bit.
   - This forces malloc to consolidate the chunk backwards during the next free.

2. **Prepare Counterfeit Pointers**:
   - Set up counterfeit `fd` and `bk` pointers in an allocated chunk.
   - Use the `prev_size` field of the targeted chunk to direct the backward consolidation attempt to these counterfeit pointers.

3. **Trigger Backward Consolidation**:
   - Free the target chunk with the cleared `prev_inuse` bit.
   - The unlink macro processes the counterfeit `fd` and `bk` pointers, resulting in arbitrary memory writes.

### Example
1. **Setup**:
   - Request chunks A and B.
   - Overflow from chunk A into chunk B's **size field**, ensuring chunk B is outside the fastbin size range.
2. **Counterfeit Metadata**:
   - Set up `fd` to point to the `__free_hook - 0x18`.
   - Set up `bk` to point to shellcode located elsewhere in memory.
   - Modify chunk B's `prev_size` to aim the consolidation at chunk A.
3. **Execute**:
   - Clear chunk B's `prev_inuse` bit using the overflow.
   - When chunk B is freed, the unlink macro writes:
     - The shellcode address to `__free_hook`.
     - The address of `__free_hook - 0x18` into the shellcode's 3rd quadword.
4. **Shellcode Execution**:
   - Trigger a call to `free()` to execute the shellcode.

---

## **Code Example**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Step 1: Allocate two chunks
    void *chunkA = malloc(0x80); // Chunk A
    void *chunkB = malloc(0x80); // Chunk B

    // Step 2: Overflow from chunkA into chunkB's metadata
    memset(chunkA, 'A', 0x80);
    *((size_t *)((char *)chunkA + 0x80)) = 0x90; // Overwrite chunkB size
    *((size_t *)((char *)chunkA + 0x88)) = (size_t)chunkA; // Fake fd
    *((size_t *)((char *)chunkA + 0x90)) = (size_t)&__free_hook - 0x18; // Fake bk

    // Step 3: Free chunkB
    free(chunkB);

    // Step 4: Allocate two more chunks to overwrite __free_hook
    void *chunkC = malloc(0x80); // Allocates chunkA
    void *chunkD = malloc(0x80); // Allocates over __free_hook

    // Step 5: Overwrite __free_hook with shellcode address
    void (*shellcode)() = (void (*)())malloc;
    memcpy(chunkD, &shellcode, sizeof(shellcode));

    // Step 6: Trigger shellcode execution
    free(chunkC);

    return 0;
}
```

### Output
When executed, the shellcode is triggered during the `free(chunkC)` call, demonstrating the exploitation of the unsafe unlink mechanism.

---

## **Approach**
- Exploit the `unlink` macro to process designer-controlled `fd` and `bk` pointers, resulting in reflected writes.
- **Forward Consolidation**: The same approach applies, but requires stricter heap control.

---

## **Limitations**

### Compatibility
- **Glibc Versions**: This technique is only effective against **glibc versions <= 2.3.3**.
  - Glibc 2.3.4 (released in 2004) introduced **safe unlinking**, which verifies `fd` and `bk` pointers before processing.

### Modern Protections
- **NX/DEP**: Introduced in 2003 (AMD) and 2004 (Intel), these protections make exploitation harder by preventing code execution on non-executable memory regions.
- **ASLR**: Address Space Layout Randomization complicates precise targeting of heap structures.

---

## **Conclusion**
The Unsafe-Unlink technique showcases the risks of unverified metadata manipulation in heap allocators. While modern mitigations have rendered this technique largely obsolete, understanding it remains valuable for historical context and research into heap exploitation techniques.