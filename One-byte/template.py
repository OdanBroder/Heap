#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./one_byte', checksec=False)

libc = ELF('../.glibc/glibc_2.23/libc.so.6x', checksec=False)

index = 0

gs = """
b *main
b *main+244
b *main+311
b *main+415
b *main+480
b *main+560
b *main+652
b *main+713
b *main+788
"""

def info(mes):
    return log.info(mes)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.remote:
        return remote('', )
    else:
        return process(elf.path)

def malloc():
    global index
    io.sendline(b'1')
    io.recvuntil(b'> ')
    index += 1
    return index - 1
    
def free(index):
    io.sendline(b'2')
    io.sendlineafter(b'index: ', str(index).encode())
    io.recvuntil(b'> ')

def edit(index, data):
    io.sendline(b'3')
    io.sendlineafter(b'index: ', str(index).encode())
    io.sendlineafter(b'data: ', data)
    io.recvuntil(b'> ')

def read(index):
    io.sendline(b'4')
    io.sendlineafter(b'index: ', str(index).encode())
    output = io.recv(0x58)
    io.recvuntil(b'> ')
    return output

def quit():
    io.sendline(b'5')
    
io = start()
io.recvuntil(b'> ')

io.interactive()
