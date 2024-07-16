---
title: 'Linux Heap Exploitation - Part 1'
disqus: Hackmd
---

# House of force


## Overall
![image](https://hackmd.io/_uploads/BJ5ez5Ur0.png)
 
**When a program allocates memory from the heap, the operating system allocates a block of physical memory (or a combination of physical and disk memory) and assigns a virtual address to it. This virtual address becomes part of the process's virtual address space and can be used by the program to access the allocated memory.**

- ***Virtual Memory (VA)*** 
    - It's a memory management technique employed by operating systems to provide processes with the illusion of having more contiguous physical memory (RAM) than is actually available.
    - The operating system maintains a translation table that maps virtual addresses used by a process to physical addresses in RAM or on secondary storage (like a hard disk).
    - This allows processes to use more memory than physically present by swapping data between RAM and disk as needed.
- ***Heap***
    - The heap is a region of memory within a process's virtual address space. 
    - It's managed dynamically during program execution. Programs can allocate and deallocate memory from the heap using functions like malloc (allocate) and free (deallocate) in C/C++.
    - The heap is typically used to store dynamically allocated objects or data structures whose size is not known at compile time.
- The heap itself is not a separate address space. It exists within the process's virtual address space managed by the operating system's virtual memory mechanism. 


***In GLIBC versions < 2.29***, top chunk size fields are not subject to any integrity checks during allocations. If a top chunk size field is overwritten using e.g. an overflow and replaced with a large value, subsequent allocations from that top chunk can overlap in-use memory. Very large allocations from a ***corrupted top chunk can wrap around the VA space in GLIBC versions < 2.30***.
- For example, a top chunk starts at address 0x405000 and target data residing at address 0x404000 in the program’s data section must be overwritten. Overwrite the top chunk size field using a bug, replacing it with the value 0xfffffffffffffff1. Next, calculate the number of bytes needed to move the top chunk to an address just before the target. The total is 0xffffffffffffffff - 0x405000 bytes to reach the end of the VA space, then 0x404000 - 0x20 more bytes to stop just short of the target address. 


## Approach

- ***Overwrite a top chunk size field*** with a *large value*, ***then request enough memory*** to bridge the gap between the top chunk and target data. ***Allocations*** made in this way can wrap around the VA space, allowing this technique to target memory at a lower address than the heap.

- Each of malloc's core functions, such as malloc() and free(), has an associated hook which takes the form of a writable function pointer in GLIBC's data section. Under normal circumstances these hooks can be used by developers to do things like implement theirown memory allocators or to collect malloc statistics.

## Further use 


- ***If the target resides on the same heap as the corrupt top chunk***, leaking a heap address is not required, the allocation can wrap around the VA space back onto the same heap to an address relative to the top chunk. 



- The malloc hook is a viable target for this technique because passing arbitrarily large requests to malloc() is a prerequisite of the House of Force. Overwriting the malloc hook with the address of system(), then passing the address of a “/bin/sh” string to malloc masquerading as the request size becomes the equivalent of system(“/bin/sh”).

 

## Limitations

- ***GLIBC version 2.29*** introduced a top chunk size field sanity check, which ensures that the top chunk size does not exceed its arena’s system_mem value. 
- ***GLIBC version 2.30*** introduced a maximum allocation size check, which limits the size of the gap the House of Force can bridge. 


# Fastbin dup

## Overall 
![image](https://hackmd.io/_uploads/HybqwqIHC.png)


- The fastbin double-free check only ensures that a chunk being freed into a fastbin is not already the first chunk in that bin, if a different chunk of the same size is freed between the double-free then the check passes. 

- For example, request chunks A & B, both of which are the same size and qualify for the fastbins when freed, then free chunk A. If chunk A is freed again immediately, the fastbin double-free check will fail because chunk A is already the first chunk in that fastbin. Instead, free chunk B, then free chunk A again. This way chunk B is the first chunk in that fastbin when chunk A is freed for the second time. Now request three chunks of the same size as A & B, malloc will return chunk A, then chunk B, then chunk A again. 

- This may yield an opportunity to read from or write to a chunk that is allocated for another purpose. Alternatively, it could be used to tamper with fastbin metadata, specifically the forward pointer (fd) of the double-freed chunk. This may allow a fake chunk to be linked into the fastbin which can be allocated, then used to read from or write to an arbitrary location. Fake chunks allocated in this way must pass a size field check which ensures their size field value matches the chunk size of the fastbin they are being allocated from. 
- Watch out for incompatible flags in fake size fields, a set NON_MAIN_ARENA flag with a clear CHUNK_IS_MMAPPED flag can cause a segfault as malloc attempts to locate a non-existent arena. 


## Approach

Leverage a ***double-free bug*** to coerce malloc into ***returning the same chunk twice***, without freeing it in between. This technique is typically capitalised upon by corrupting fastbin metadata to ***link a fake chunk into a fastbin***. This fake chunk can be allocated, then program functionality could be used to ***read from or write to an arbitrary memory location.***
## Further use 

***The malloc hook*** is a good target for this technique, the 3 most-significant bytes of the _IO_wide_data_0 vtable pointer can be used in conjunction with part of the succeeding padding quadword to form a **reliable 0x7f size field.** 
- **This works because allocations are subject neither to alignment checks nor to flag corruption checks.**  


## Limitations 

***The fastbin size field check*** during allocation limits candidates for fake chunks. 


# Unsafe unlink

## Overall
![image](https://hackmd.io/_uploads/HJQPakuSC.png)


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



# Safe unlink
## Overall
![image](https://hackmd.io/_uploads/H1ERASuS0.png)


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


# House of Orange

***This challenge is in the Linux Heap Exploitation - Part 1, and it is worth to write something about it.***

## Overall

![image](https://hackmd.io/_uploads/ByHYuw240.png)


![image](https://hackmd.io/_uploads/BJiEGP24A.png)

Challenge gives me 4 options as the image above.

![image](https://hackmd.io/_uploads/HJ2e7P2VR.png)
- If i only request malloc(small) and edit with data: aaaaa

![image](https://hackmd.io/_uploads/SktOfvnE0.png)

- malloc(small): call malloc() with the size 0x20
- malloc(large): call malloc() with the size 0xfd0
- edit: write data to the start of small chunk
- quit: simply exit the program.

***However the challenge doesn't give me free()...***

### Bug


![image](https://hackmd.io/_uploads/Hk-TQP34C.png)

***As you see, I can overwrite the heap.***



## Approach
### Create free chunk

The challenge doesn't give me free option(), but it allows me to overwrite the heap(chunk size, prev_size,..... include of top chunk size).


![image](https://hackmd.io/_uploads/HyYzBD34C.png)
- Document for ***top chunk*** in ***HeapLab - GLIBC Heap Exploitation.pdf***

I can create an unsorted bin by **overwriting the size field of the top chunk** -> **request a larger size** than this size.

Main Arena will use brk syscall to request the new memory from kernel. Because the new memory doesn't border the end of the heap. Thus, malloc assume that the kernel was unable to map contiguous memory from the heap. Since the new memory is larger, malloc starts a new heap from it(set top chunk pointer to the new memory) and so as not to waste space, it frees the old top chunk. 

#### Notice
> Malloc keeps track of the remaining memory in a top chunk using its size field, the prev_inuse bit of 
> which is always set. A top chunk always contains enough memory to allocate a minimum-sized chunk 
> and always ends on a page boundary. 

#### Overwiting top chunk size with: **0x1000 - 0x20 + 1**, then request the large size

#### The result

![image](https://hackmd.io/_uploads/SJEwdPhVC.png)


### Find the target

#### Unsortedbin attack
I can write the address of unsortedbin to somewhere(fd + 0x10) by following bk pointer to overwrite this address to fd poiner. 

#### Target file stream

If the program uses fopen or something else, the file steam will be used. Or if not, there will also be one because the program always contains stdin(0), stdout(1), and stderr(2).

![image](https://hackmd.io/_uploads/SklBiw240.png)


***However, what if I target one of the standard I/O vtable pointer.***
- Our unsortedbin attack would replace that vtable pointer with the address of the main arena's unsortedbin. Then the next time a standard I/O member function was called, the main arena would be treated as a vtable.
- The main arena consists primarily of empty linked lists at this point, and attempting to execute those addresses would just lead to a general protection fault as we tried to execute memory marked as non-executable. Even if I were to populate some of those bins with pointers to heap memory by sorting chunks into them, heaps are no more executable than arenas.


***Fortunately, I have _IO_list_all pointer(the head of a list of every file stream).***

![image](https://hackmd.io/_uploads/SJf72PnEA.png)

![image](https://hackmd.io/_uploads/rk-r2PnVA.png)

- This process has open and it's used when GLIBC needs to perform an operation on all open file streams, typically cleanup procedures. One of those cleanup procedures is performed when a program exits, either via the GLIBC exit() function or by returning from its main() function.

**Conclusion**
- I will target the _IO_list_all pointer with our unsortedbin attack, replacing it with a pointer into the main arena, then we exit the program. As the program exits and GLIBC cleans up, it will attempt to flush the buffers of any open file streams.
- It does this by iterating over every file stream in the _IO_list_all list, determining whether its buffers require flushing, and if so, calling a specific member function named 'overflow' on that file stream, nothing to do with this sort of overflows.



### Set up

![image](https://hackmd.io/_uploads/ryPTeu240.png)

Now, I have what I want. 

![image](https://hackmd.io/_uploads/ByXv-_n40.png)
- However, the program get segmentation fault. 
- And _IO_flush_all_lockp() uses to determine whether a file stream requires flushing.
- The reason for that is this file stream doesn't pass the check.
    - ![image](https://hackmd.io/_uploads/SJH3-u340.png)
    - After all this function is trying to treat the main arena like a file stream. The line containing _IO_OVERFLOW in all caps is the one calling the 'overflow' member function. The first argument, 'fp', represents the file stream overflow() is being called from.
    - There are two checks prior to this line, each one of which must pass in order for overflow() to be called. 
        - The first check passes if the '_mode' field of the file stream is less than or equal to zero and its _IO_write_ptr field is larger than its _IO_write_base field. 
        - The second check _mode larger than zero. 
    - It will fail the first check due to the latter and the second check due to the former.
- In this case _IO_flush_all_lockp() won't call this file stream's overflow() function and will instead move on to the next stream the current stream's _chain pointer(_chain points back into the main arena).
    - ![image](https://hackmd.io/_uploads/S1NAp_hVR.png)
    - ![image](https://hackmd.io/_uploads/SJuIHOhVA.png)
    - ***The bk of the 0x60 smallbin is what's being treated as this rogue file stream's _chain pointer.***   
 
- So if we change the size field of the old top chunk from 0x21 to 0x61 before our unsortedbin attack, the old top chunk will be sorted into the 0x60 smallbin rather than being allocated, and end up as the _chain pointer of the rogue file stream overlapping the main arena. This allows me to forge our own fake file stream on the heap, providing our own vtable pointer and vtable entries

***Let's build the fake file stream.***

Change my script little

```python=
size = 0x61
fd = 0x0
bk = libc.sym['_IO_list_all'] - 0x10

unsortedbin_attack = b'Y'*16 +\
flag + p64(size) +\
p64(fd)  + p64(bk) +\
b'a'*8 + b'b'*8
edit(unsortedbin_attack)
malloc_small()
quit()
```

![image](https://hackmd.io/_uploads/SkjaLuhNR.png)

![image](https://hackmd.io/_uploads/HyslvO2V0.png)

**Now, we need to pass the check**
- `fp > write_ptr > write_base`
- `fp -> mode <= 0`

Afterwards, I need to set up to call system("/bin/sh"). 
- I provide a vtable pointer to a vtable in which the overflow() entry is populated by the function. 
- When the overflow() function is called, its first argument is the address of the file stream it's called from. That means if I write the string "/bin/sh" into the first quadword of our file stream, which is where the '_flags' field resides, then point the overflow() vtable entry at the GLIBC system() function, the call becomes system("/bin/sh") and I get a shell without the need for a one-gadget.


# One byte

## Overall
![image](https://hackmd.io/_uploads/HkhlxJlHR.png)

- Full armour

![image](https://hackmd.io/_uploads/Skmv11gHR.png)

- No leak libc, heap.

![image](https://hackmd.io/_uploads/H1rYyygH0.png)

- No double free.

![image](https://hackmd.io/_uploads/BJLJl1xBC.png)

- No UAF.

### malloc
![image](https://hackmd.io/_uploads/SJCNgkxrA.png)

- As you see, it calls calloc instead of malloc with a size of 0x58 (0x60 for chunk).
- Memory blocks allocated by the calloc function are always initialized to zero.

### free

#### It is simple that the program call free to free the chunk at index from user input.

### edit

#### It takes input from user(index) to write data to this index chunk.

![image](https://hackmd.io/_uploads/B1xOG1xrA.png)

- Input with a size of 0x59.

### read

#### It is simple that the program call write data from the chunk at index to stdout.

### quit

#### Leave the program.

## Bug

#### Call alloc to allocate 0x58 size; however, it take input from the user with 0x59 size. This mean that I can overwrite one byte.




## Approach

#### Everything will be better if I have the address of libc and heap

### Leak libc

***target:*** unsortedbin + remainder. 

#### I can overwrite one byte, so I can control the size of the succeeding chunk. Thus, if I overwrite the size of the chunk with the larger size, then free it, this free chunk will overlap other chunk that doesn't free. 

```python=
chunk_A = malloc()
chunk_B = malloc()
chunk_C = malloc()
chunk_D = malloc()

edit(chunk_A, p8(0)*0x58 + p8(0xc1))
free(chunk_B)

```

![image](https://hackmd.io/_uploads/r1vfDkgHA.png)
-  After overwrite

![image](https://hackmd.io/_uploads/HyxIw1eHC.png)
- After free 

***Now, I can write and read data in chunk_C, which is overlaped by free chunk, so I can leak data from this free chunk.***


Add some lines of code and see the result

```python=
chunk_B2 = malloc()

unsortedbin_data = read(chunk_C)
unsortedbin = u64(unsortedbin_data[0:8])
info("unsortedbin: " + hex(unsortedbin))
```
![image](https://hackmd.io/_uploads/ByE4qJxr0.png)

![image](https://hackmd.io/_uploads/BkQPqklrA.png)

### Leak heap

**target:** fastbin dup

Add some lines of code

```python=
chunk_C2 = malloc()
free(chunk_A)
free(chunk_C2)

fastbin_data = read(chunk_C)
heap = u64(fastbin_data[0:8])
info("heap: " + hex(heap))
```

![image](https://hackmd.io/_uploads/r1iBnJeHR.png)

![image](https://hackmd.io/_uploads/SySiaJxrR.png)


### The house of orange

***target:*** overwrite vtable of _IO_list_all to trigger overflow function in vtable for pop shell.
Because I can overwrite one byte(size of chunk), I can control heap to create fake file stream.

```python=
# house of oragne
chunk_C3 = malloc()
chunk_A2 = malloc()

edit(chunk_A2, p8(0)*0x58 + p8(0xc1))
free(chunk_B2)

chunk_B3 = malloc()

# string "/bin/sh" to _flag size field
edit(chunk_B3, p64(0)*10 + b'/bin/sh\x00')

payload = \
p64(0) + p64(libc.sym['_IO_list_all'] - 0x10) +\
p64(1) + p64(2) 

edit(chunk_C3, payload)

edit(chunk_E, p64(libc.sym['system']) + p64(heap + 0x178))

malloc()
```

**My configure struct**


![image](https://hackmd.io/_uploads/rk_sIMxH0.png)


![image](https://hackmd.io/_uploads/BJfnIzeS0.png)


![image](https://hackmd.io/_uploads/H1KnIzeB0.png)


**However, there will be a mistake when I do it. Notice that triggers can happen when sorting this fake chunk, not allocating it (the program will not abort and the location of this will not reside in 0x60 bk small bin)**

![image](https://hackmd.io/_uploads/BkIZ8fgSC.png)

- IO_list_all

![image](https://hackmd.io/_uploads/BkYm8flHR.png)

- IO_list_all.file._chain


***I set up fake file stream successfully; however, I need to trigger to move it into _IO_list_all***

#### Trigger size

![image](https://hackmd.io/_uploads/rkC6Pzer0.png)

***Method 1***
_IO_list_all -> _chain: 0x60 bk small bin -> _chain: 0xb0 small bin

***Set size chunk C to 0xb1***

***Method 2***


```cpp=
          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          /* place chunk in bin */
```

- The exact fitting chunks are allocated from the unsortedbin, otherwise they're sorted into the appropriate small or large bin. The 'nb' variable represents the normalized request size, it's the result of malloc rounding up your request to the nearest actual chunk size.
- For example, if I request 3 bytes, 'nb' would hold the value 0x20.
- In the case of our challenge binary 'nb' is always 0x60.
- The 'size' variable represents the size of the unsorted chunk currently under inspection. malloc masks off the chunk's flags prior to this comparison to stop them from interfering.
- ***But chunk size fields only hold three flags, the fourth least-significant bit is neither a flag nor does it contribute to a chunk's size. During unsorted bin searches it is not masked off prior to this comparison because there's no good reason for it to ever be set in the first place.***
- So if we set the fourth least-significant bit of our 0x60 chunk, giving it a size field of 0x68, or 0x69 if you want to keep the prev_inuse flag, **it won't be considered an exact fit during requests for 0x60-sized chunks**. However, i**t will sort this chunk to 0x60 small bin.**
- Furthermore, the code responsible for sorting chunks into their respective bins does mask off, specifically it rotates away, the entire low order nybble of their size field, meaning that our chunk with the 0x68 size field will still be correctly sorted into the 0x60 smallbin.

***Set size chunk C to 0x68***

