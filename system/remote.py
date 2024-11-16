from pwn import *


context.arch = "amd64" # x86-64 아키텍처
context.arch = "i386"  # x86 아키텍처
context.arch = "arm"   # arm 아키텍처

#p = process('./test')  # 로컬 바이너리 'test'를 대상으로 익스플로잇 수행
p = remote('example.com', 31337)  # 'example.com'의 31337 포트에서 실행 중인 프로세스를 대상으로 익스플로잇 수행

p.send(b'A')  # ./test에 b'A'를 입력
p.sendline(b'A') # ./test에 b'A' + b'\n'을 입력
p.sendafter(b'hello', b'A')  # ./test가 b'hello'를 출력하면, b'A'를 입력
p.sendlineafter(b'hello', b'A')  # ./test가 b'hello'를 출력하면, b'A' + b'\n'을 입력

data = p.recv(1024)  # p가 출력하는 데이터를 최대 1024바이트까지 받아서 data에 저장
data = p.recvline()  # p가 출력하는 데이터를 개행문자를 만날 때까지 받아서 data에 저장
data = p.recvn(5)  # p가 출력하는 데이터를 5바이트만 받아서 data에 저장
data = p.recvuntil(b'hello')  # p가 b'hello'를 출력할 때까지 데이터를 수신하여 data에 저장
data = p.recvall()  # p가 출력하는 데이터를 프로세스가 종료될 때까지 받아서 data에 저장

s32 = b"ABCD"
s64 = b"ABCDEFGH"

print(hex(u32(s32)))
print(hex(u64(s64)))

p.interactive()

context.log_level = 'error' # 에러만 출력
context.log_level = 'debug' # 대상 프로세스와 익스플로잇간에 오가는 모든 데이터를 화면에 출력
context.log_level = 'info'  # 비교적 중요한 정보들만 출력

code = shellcraft.sh() # 셸을 실행하는 셸 코드 
code = asm(code)       # 셸 코드를 기계어로 어셈블
print(code)










































