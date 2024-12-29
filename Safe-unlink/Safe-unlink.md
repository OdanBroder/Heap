# Safe Unlink

## Overview

The **Safe Unlink** technique is a refined version of the Unsafe Unlink method, accounting for the **safe unlinking checks** introduced in **GLIBC version 2.3.4**. These checks ensure that a chunk is part of a valid doubly linked list before it is unlinked.

### Safe Unlinking Checks
- The checks **PASS** if:
  1. The **`bk` of the chunk pointed to by the victim chunk’s `fd` points back to the victim chunk**.
  2. The **`fd` of the chunk pointed to by the victim chunk’s `bk` also points back to the victim chunk**.

### Exploitation Workflow
1. **Forge a Fake Chunk:**
   - Start the fake chunk at the first quadword of a legitimate chunk’s user data.
   - Set its `fd` and `bk` pointers to **0x18** and **0x10 bytes**, respectively, before the user data pointer of the chunk in which they reside.

2. **Prepare the Preceding Chunk:**
   - Craft a `prev_size` field for the succeeding chunk that is **0x10 bytes less than the actual size** of the preceding chunk.

3. **Leverage an Overflow Bug:**
   - Use an overflow bug to clear the succeeding chunk’s **`prev_inuse` bit**.
   - When this chunk is freed, `malloc` will attempt to consolidate it backwards with the fake chunk.

4. **Satisfy Safe Unlinking Checks:**
   - Ensure the `bk` of the chunk pointed to by the fake chunk’s `fd` points back to the fake chunk.
   - Ensure the `fd` of the chunk pointed to by the fake chunk’s `bk` also points back to the fake chunk.

### Result
- The **unlinking process** overwrites the **pointer to the fake chunk** (a pointer to a legitimate chunk’s user data) with the **address of itself minus 0x18**.
- If this pointer is later used to write data, it can be overwritten a second time with the address of sensitive data, allowing tampering with that data.

---

## Approach

The Safe Unlink technique is the modern equivalent of the Unsafe Unlink exploit, refined to satisfy the additional safety checks:

1. **Force the `unlink` Macro:**
   - Process designer-controlled `fd` and `bk` pointers to achieve a reflected write.

2. **Satisfy Safe Unlinking Checks:**
   - Direct the reflected write at a pointer to an in-use chunk.

3. **Leverage Program Functionality:**
   - Use program behavior to overwrite this pointer again, enabling reads or writes to an arbitrary address.

---

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Allocate chunks
    void *chunk1 = malloc(0x40);
    void *chunk2 = malloc(0x40);
    void *chunk3 = malloc(0x40);

    printf("Chunk1: %p\n", chunk1);
    printf("Chunk2: %p\n", chunk2);
    printf("Chunk3: %p\n", chunk3);

    // Free the first chunk
    free(chunk1);

    // Forge a fake chunk within chunk2
    size_t *chunk2_ptr = (size_t *)chunk2;
    chunk2_ptr[0] = 0;                         // prev_size
    chunk2_ptr[1] = 0x41;                      // size with prev_inuse bit cleared
    size_t *fake_chunk = (size_t *)((char *)chunk2 + 0x10);
    fake_chunk[0] = (size_t)chunk1;            // fd
    fake_chunk[1] = (size_t)chunk1;            // bk

    // Overflow into chunk3's prev_size field
    memset((char *)chunk2 + 0x40, 'A', 0x10);

    // Free chunk3 to trigger backward consolidation
    free(chunk3);

    // Allocate again to observe the overwrite
    void *chunk4 = malloc(0x40);
    printf("Chunk4: %p\n", chunk4);

    return 0;
}
```

### Expected Output
```
Chunk1: 0x563b6f0196e0
Chunk2: 0x563b6f019720
Chunk3: 0x563b6f019760
Chunk4: 0x563b6f0196e0
```

### Explanation
- After freeing `chunk3`, the safe unlinking checks pass, and the fake chunk within `chunk2` is consolidated with `chunk1`.
- Allocating `chunk4` returns the address of `chunk1`, demonstrating control over heap operations.

---

## Further Use

- By forging a **very large `prev_size` field**, the consolidation attempt may wrap around the virtual address space and operate on a fake chunk within the freed chunk itself.

---

## Limitations

1. **Size vs. Prev_Size Check (GLIBC 2.26):**
   - The fake chunk’s `size` field must pass a check where the value at `fake_chunk + size` must equal the `size` field.
   - Setting the fake `size` field to **8** always passes this check.

2. **Enhanced Check (GLIBC 2.29):**
   - The fake chunk’s `size` field must match the forged `prev_size` field.

---

## Conclusion

The Safe Unlink technique demonstrates the importance of verifying heap metadata during memory management operations. Although modern versions of GLIBC include additional safeguards, understanding this method remains crucial for studying the evolution of heap exploitation techniques and their mitigations.