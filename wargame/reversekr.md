# Easy Crack

It splits our input to compare. Find the compare condition and recover the flag.

# KeygenMe

Quest: `Find the Name when the Serial is 5B134977135E7D13`

The core code is here:
```c
v6 = 16;
v7 = 32;
v8 = 48;
for ( i = 0; v3 < (signed int)strlen(&input_name); ++i )
{
  if ( i >= 3 )
    i = 0;
  sprintf(&serial_num, "%s%02X", &serial_num, *(&input_name + v3++) ^ *(&v6 + i));
}
```

The script iterates each byte of our input and xor it with `v6`, `v7`, and `v8` depends on its mod by `3`:
```python
 num = "5B 13 49 77 13 5E 7D 13".split(" ")
 for i in range(0, len(num)):
     num[i] = int(num[i], 16)

 xor = [16, 32, 48]

 i = 0
 for v3 in range(0, len(num)):
     if (i >= 3):
         i = 0
     for ch in range(0x20, 0x7e):
         if (num[v3] == (ch ^ xor[i])):
             print(chr(ch), end = "")
             break
     i = i + 1
```

# Easy Unpack

There must be a `push ebp` in the *OEP*. We can track that `0x401150` is the correct address.

# Easy ELF

The program loads main via `.got`. But we can locate the `main` function quickly via IDA pro's *Functions window*

The key comparison, and `0x804A020` starts our input:
```c
_BOOL4 sub_8048451()
{
  if ( byte_804A021 != '1' )
    return 0;
  byte_804A020 ^= 0x34u;
  byte_804A022 ^= 0x32u;
  byte_804A023 ^= 0x88u;
  if ( byte_804A024 != 'X' )
    return 0;
  if ( byte_804A025 )
    return 0;
  if ( byte_804A022 != 0x7C )
    return 0;
  if ( byte_804A020 == 0x78 )
    return byte_804A023 == -35;
  return 0;
}
```
So, we can decrypt one by one:
```python
# An XOR helper function
def find(target, xor):
    for i in range(0x20, 0x7e):
        if i ^ xor == target:
            print(chr(i), end = "")
            break

find(0x78, 0x34)
print("1", end = "")
find(0x7c, 0x32)
find(0xff - 35 + 1, 0x88)
print("X", end = "")
```

# Replace

It's a self modified program, in the checker functiomn:
```c
BOOL __stdcall DialogFunc(HWND hDlg, UINT a2, WPARAM a3, LPARAM a4)
{
  BOOL result; // eax

  if ( a2 != 273 )
    return 0;
  if ( (unsigned __int16)a3 == 2 )
  {
    EndDialog(hDlg, 2);
    result = 1;
  }
  else if ( (unsigned __int16)a3 == 1003 )
  {
    num_value = GetDlgItemInt(hDlg, 1002, 0, 0);
    inc_num();
    simple_inc(&loc_40469F);
    *(_DWORD *)inc_num = 0C39000C6h; // Modification here
    inc_num();
    inc_num();
    *(_DWORD *)inc_num = 1768;
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
```

It will change the instruction of `inc_num` function. The modification is interesting, it equals to `mov byte [eax], 0x90; ret`. And `eax` is equal to `num_value`. The first call modfication the address pointed by `eax` and the second call changes one byte after it if you read the assembly code:
```asm
call    inc_num
inc     eax
call    inc_num
```

Since `0x90` is `ret`, we can use the overwrite to patch `jmp` here:
```asm
00401071                 jmp     short loc_401084
00401073                 push    offset String   ; "Correct!"
00401078                 push    3E9h            ; nIDDlgItem
0040107D                 push    esi             ; hDlg
0040107E                 call    ds:SetDlgItemTextA
```

The next tricky part is the `inc_num` function. If u force IDA to covert junk data to assmenler, u will see:
```asm
add     num_value, 601605C7h
inc     eax
add     bl, ch
pusha
nop
popa
call    $+5
```

`num_value` is actuall added more than *2* (twice `inc`). But `1 + 1 + 0x601605C7 + 1 + 1`. We need to do a simple math to calculate the correct offset: `InputKey + 1 + 1 + 0x601605C7 + 1 + 1 = 0x401071`. Ignoring the overflow part, we can get `2687109798` (decimal format).

# ImagePrc

