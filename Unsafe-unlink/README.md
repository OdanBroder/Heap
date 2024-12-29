## Overall
- ***During chunk consolidation*** the chunk already ***linked into a free list is unlinked from that list*** via the unlink macro. The unlinking process is a reflected ***WRITE*** using the ***chunk’s forward (fd) and backward (bk) pointers***
    - The victim bk is copied over the bk of the chunk pointed to by the victim fd.
    - The victim fd is written over the fd of the chunk pointed to by the victim bk. 
    - If a chunk with designer controlled fd & bk pointers is unlinked, this write can be manipulated. 
- One way to achieve this is via an ***overflow into a chunk’s size field***, which is used to ***CLEAR*** ***its prev_inuse bit***. When the chunk with the clear prev_inuse bit is freed, malloc will attempt to ***consolidate it backwards***. A designer-supplied prev_size field can aim this consolidation attempt at an allocated chunk where counterfeit fd & bk pointers reside. 
- For example
    - Request chunks A & B, chunk A overflows into chunk B’s size field and chunk B is outside fastbin size range. 
    - Prepare counterfeit fd & bk pointers within chunk A, the fd points at the free hook – 0x18 and the bk points to shellcode prepared elsewhere. 
    - Prepare a prev_size field for chunk B that would cause a backward consolidation attempt to operate on the counterfeit fd & bk. 
    - Leverage the overflow to clear chunk B’s prev_inuse bit. 
- When chunk B is freed the ***clear prev_inuse bit*** in its size field causes malloc to ***read chunk B’s prev_size field and unlink the chunk that many bytes behind it***. When the unlink macro operates on the counterfeit fd & bk pointers, it **writes the address of the shellcode to the free hook and the address of the free hook – 0x18 into the 3rd quadword of the shellcode.** 
    - The shellcode can use a jump instruction to skip the bytes corrupted by the fd. 
    
**Triggering a call to free() executes the shellcode.** 


## Approach 
- Force the unlink macro to process designer-controlled fd/bk pointers, leading to a reflected write. 
## Further use 


It is possible to use a ***prev_size field of 0*** and ***craft the counterfeit fd & bk pointers*** within chunk. The same technique can be applied to forward consolidation but requires stricter heap control.

## Limitations 


This technique can only be leveraged against ***GLIBC versions <= 2.3.3***, safe unlinking was introduced in GLIBC version 2.3.4 in 2004 and GLIBC versions that old are not common. This technique was originally leveraged against platforms without NX/DEP and is described as such here. In 2003 AMD introduced hardware NX support to their consumer desktop processors, followed by Intel in 2004, systems without this protection are not common.