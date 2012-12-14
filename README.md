ropdumper
=========


A tool to find ROP gadgets hidden in binary files.


**Q) What is a "normal" ROP gadget?**


A) It's a short sequence (usually 2 or 3 instructions) of x86 assembly instructions ending with "ret" which is very

usefull to exploit stack overflow when the stack is "non-executable" (which is the case almost everywhere now)


**Q) What is a "hidden" ROP gadget?**


A) Let's take an example: 


have a look at the following assembly code snippet:

```asm
8049166: 66 90                 xchg   %ax,%ax
8049168: 80 3c 1f c3           cmpb   $0xc3,(%edi,%ebx,1)
```

(This snippet comes from the output of objdump -D ropdumper)

The first column is the address of the instruction

The second column is the hexadecimal code (machine code) of the x86 instruction

The last column is the assembly instruction itself, in ASCII human readable format, with mnemonic and operands etc.



You can notice the presence of the value 0xc3 as the last byte of the second instruction.

This value is really important because it happens to be the machine code for the "ret" instruction.

So let's assume we jump in the middle of the following instruction: 

```asm
cmpb $0xc3,(%edi,%ebx,1)
```

For instance at address 0x8049166a. The CPU would see the following machine code sequence: 

```
1f c3
```

let's see what this means in term of x86 instruction : 

```bash
$ echo -ne "\x1f\xc3" > test.bin
$ objdump -m i386 -b binary -D test.bin
```

```asm
00000000 <.data>:
   0: 1f                    pop    %ds
   1: c3                    ret 
```

*BINGO!*


You can see that jumping in the middle of an instruction can actually lead the CPU to execute totally different

instructions.

In this case, we just found a ROP gadget :) (an instruction followed by a ret)


***Q) What's the big deal with those "ROP gadgets"??***


The previous example is really interesting as a ROP gadget because it pops a value from the stack and writes it

into a register, so this makes a perfect ROP to write any value into the given register.

You just need to put your value in your overflowing buffer on the stack and then overwrite the return address of

the function with the address of this ROP gadget and you will be able to control what gets written to %ds register.


If you find enough ROP gadgets you can chain them together and make the code basically do whatever you want ;)


How to use ropdumper: 

```bash
$ ./ropdumper path/to/binary/to/inspect
```

Fetching and Compiling: 

```bash
$ git clone https://github.com/fallen/ropdumper.git
$ cd ropdumper
$ make
```

Dependency: 


- lib bfd


Installing dependency:


+ Debian / Ubuntu

```bash
$ sudo apt-get install libbfd-dev
```
