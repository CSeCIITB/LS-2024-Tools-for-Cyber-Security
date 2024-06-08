#!/usr/bin/python -I

import sys
import collections
import string
import random
import struct
import textwrap
from collections import defaultdict
from typing import List, Optional
import colorama
import pwnlib.context
import pwnlib.asm
from unicorn import *
from unicorn.x86_const import *
from capstone import *

pwnlib.context.context.arch = "amd64"


def print_many_lines(text):
    print(textwrap.dedent(text))


class ASMBase:
    """
    ASM:
    A set of levels to teach people the basics of x86 assembly:
    - registers_use
    - stack
    - functions
    - control statements
    Level Layout:
    === Reg ===
    1. Reg write
    2. Reg modify
    3. Reg complex use
    4. Integer Division
    5. Modulo
    6. Smaller register access
    === Bits in Registers ===
    7. Shifting bits
    8. Logic gates as a mov (bit logic)
    9. Hard bit logic challenge
    === Mem Access ===
    10. Read & Write from static memory location
    11. Sized read & write from static memory
    12. R/W to dynamic memory (stored in registers)
    13. Access adjacent memory given at runtime
    === Stack ===
    14. Pop from stack, modify, push back
    15. Stack operations as a swap
    16. r/w from stack without pop (rsp operations)
    === Control Statements ===
    17. Unconditional jumps (jump trampoline, relative and absolute)
    18. If statement jumps (computing value based on a header in mem)
    19. Switch Statements
    20. For-Loop (summing n numbers in memory)
    21. While-Loop (implementing strlen, stop on null)
    === Functions ===
    22. Making your own function, calling ours
    23. Making your own function with stack vars (the stack frame)
    """

    BASE_ADDR = 0x400000
    CODE_OFFSET = 0
    LIB_OFFSET = 0x3000
    DATA_OFFSET = 0x4000
    LIB_ADDR = BASE_ADDR + LIB_OFFSET
    DATA_ADDR = BASE_ADDR + DATA_OFFSET
    BASE_STACK = 0x7FFFFF000000
    RSP_INIT = BASE_STACK + 0x200000
    REG_MAP = {
        "rax": UC_X86_REG_RAX,
        "rbx": UC_X86_REG_RBX,
        "rcx": UC_X86_REG_RCX,
        "rdx": UC_X86_REG_RDX,
        "rsi": UC_X86_REG_RSI,
        "rdi": UC_X86_REG_RDI,
        "rbp": UC_X86_REG_RBP,
        "rsp": UC_X86_REG_RSP,
        "r8": UC_X86_REG_R8,
        "r9": UC_X86_REG_R9,
        "r10": UC_X86_REG_R10,
        "r11": UC_X86_REG_R11,
        "r12": UC_X86_REG_R12,
        "r13": UC_X86_REG_R13,
        "r14": UC_X86_REG_R14,
        "r15": UC_X86_REG_R15,
        "rip": UC_X86_REG_RIP,
        "efl": UC_X86_REG_EFLAGS,
        "cs": UC_X86_REG_CS,
        "ds": UC_X86_REG_DS,
        "es": UC_X86_REG_ES,
        "fs": UC_X86_REG_FS,
        "gs": UC_X86_REG_GS,
        "ss": UC_X86_REG_SS,
    }

    def __init__(
        self,
        asm=None,
        registers_use=False,
        dynamic_values=False,
        memory_use=False,
        stack_use=False,
        bit_logic=False,
        ip_control=False,
        multi_test=False,
        functions=False,
        should_debug=False
    ):

        self.asm: Optional[bytes] = asm
        self.registers_use: bool = registers_use
        self.dynamic_values: bool = dynamic_values
        self.memory_use: bool = memory_use
        self.stack_use: bool = stack_use
        self.bit_logic: bool = bit_logic
        self.ip_control: bool = ip_control
        self.multi_test: bool = multi_test
        self.functions: bool = functions
        self.should_debug: bool = should_debug

        self.emu_err: Optional[str] = None
        self.emu: Optional[Uc] = None
        self.filter_list: List[str] = []
        self.exit_key = None

    def print_level_text(self):
        raise NotImplementedError

    def trace(self):
        raise NotImplementedError

    def debug(self):
        print("")



    def run(self):

        self.print_welcome()
        self.print_level_text()

        self.get_asm_from_user()

        self.create_emu()

        print("Executing your code...")
        self.print_disasm()

        won = self.trace()
        def tux_say(to_print):
            print(f"""
            {to_print} 
                \\
                    .--.
                |o_o |
                |:_/ |
                //   \\ \\
                (|     | )
                /'\\_   _/`\\
                \\___)=(___/
            """)
        if won:
            self.print_flag()
        else:
            tux_say("\nSorry, no flag :(.")

        return won

    def get_asm_from_user(self):
        if not self.asm:
            print("Please give me your assembly in bytes (up to 0x1000 bytes): ")
            self.asm = sys.stdin.buffer.read1(0x1000)
        

    def print_welcome(self):
        print(f"\nWelcome to {self.__class__.__name__}")
        print("=" * 50)
        print(
            "To interact with any level you will send raw bytes over stdin to this program.\n"
            "To efficiently solve these problems, first run it once to see what you need,\n"
            "then craft, assemble, and pipe your bytes to this program.\n"
        )

        if self.registers_use:
            print(
                "In this level you will be working with registers. You will be asked to modify\n"
                "or read from registers_use.\n"
            )

        if self.dynamic_values:
            print(
                "We will now set some values in memory dynamically before each run. On each run\n"
                "the values will change. This means you will need to do some type of formulaic\n"
                "operation with registers_use. We will tell you which registers_use are set beforehand\n"
                "and where you should put the result. In most cases, its rax.\n"
            )

        if self.memory_use:
            print(
                "In this level you will be working with memory. This will require you to read or write\n"
                "to things stored linearly in memory. If you are confused, go look at the linear\n"
                "addressing module in 'ike. You may also be asked to dereference things, possibly multiple\n"
                "times, to things we dynamically put in memory for you use.\n"
            )

        if self.bit_logic:
            print(
                "In this level you will be working with bit logic and operations. This will involve heavy use of\n"
                "directly interacting with bits stored in a register or memory location. You will also likely\n"
                "need to make use of the logic instructions in x86: and, or, not, xor.\n"
            )

        if self.stack_use:
            print(
                "In this level you will be working with the Stack, the memory region that dynamically expands\n"
                "and shrinks. You will be required to read and write to the Stack, which may require you to use\n"
                "the pop & push instructions. You may also need to utilize rsp to know where the stack is pointing.\n"
            )

        if self.ip_control:
            print(
                "In this level you will be working with control flow manipulation. This involves using instructions\n"
                "to both indirectly and directly control the special register `rip`, the instruction pointer.\n"
                "You will use instructions like: jmp, call, cmp, and the like to implement requests behavior.\n"
            )

        if self.multi_test:
            print(
                "We will be testing your code multiple times in this level with dynamic values! This means we will\n"
                "be running your code in a variety of random ways to verify that the logic is robust enough to\n"
                "survive normal use. You can consider this as normal dynamic value"
            )

        if self.functions:
            print(
                "In this level you will be working with functions! This will involve manipulating both ip control\n"
                "as well as doing harder tasks than normal. You may be asked to utilize the stack to save things\n"
                "and call other functions that we provide you."
            )

    def print_disasm(self):
        print("---------------- CODE ----------------")
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(self.asm, self.BASE_ADDR + self.CODE_OFFSET):
            print("0x%x:\t%-6s\t%s" % (i.address, i.mnemonic, i.op_str))
        print("--------------------------------------")
    
    def print_flag(self):
        def tux_say(to_print):
            print(
            f"""
        {to_print} 
        \\
        .--.
       |o_o |
       |:_/ |
      //   \\ \\
     (|     | )
    /'\\_   _/`\\
    \\___)=(___/
            """)
        with open("flag.txt", "r") as fp:
            flag = fp.read()
            tux_say(flag)

    def create_emu(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(self.BASE_ADDR, 2 * 1024 * 1024)

        mu.mem_write(self.BASE_ADDR + self.CODE_OFFSET, self.asm)

        mu.mem_map(self.BASE_STACK, 2 * 1024 * 1024)

        mu.reg_write(UC_X86_REG_RSP, self.RSP_INIT)

        mu.reg_write(UC_X86_REG_RAX, 0x0)
        mu.reg_write(UC_X86_REG_RBX, 0x0)
        mu.reg_write(UC_X86_REG_RCX, 0x0)
        mu.reg_write(UC_X86_REG_RDX, 0x0)
        mu.reg_write(UC_X86_REG_RSI, 0x0)
        mu.reg_write(UC_X86_REG_RDI, 0x0)
        mu.reg_write(UC_X86_REG_R8, 0x0)
        mu.reg_write(UC_X86_REG_R9, 0x0)
        mu.reg_write(UC_X86_REG_R10, 0x0)
        mu.reg_write(UC_X86_REG_R11, 0x0)
        mu.reg_write(UC_X86_REG_R12, 0x0)
        mu.reg_write(UC_X86_REG_R13, 0x0)
        mu.reg_write(UC_X86_REG_R14, 0x0)
        mu.reg_write(UC_X86_REG_R15, 0x0)

        self.emu = mu

    def get_rsp(self, offset=0) -> int:
        return self.emu.reg_read(UC_X86_REG_RSP) + offset

    def set_rsp(self, rsp: int) -> None:
        self.emu.reg_write(UC_X86_REG_RSP, rsp)

    def blacklist_hook(self, uc, address, size, user_data):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        i = next(md.disasm(uc.mem_read(address, size), address))

        if i.mnemonic in self.filter_list:
            self.emu_err = "fail: this instruction is not allowed: %s" % i.mnemonic
            uc.emu_stop()

    def whitelist_hook(self, uc, address, size, user_data):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        i = next(md.disasm(uc.mem_read(address, size), address))

        if i.mnemonic not in self.filter_list:
            self.emu_err = "fail: this instruction is not allowed: %s" % i.mnemonic
            uc.emu_stop()

    def add_emu_inst_filter(self, insts: List, whitelist: bool):
        self.filter_list = insts
        if whitelist:
            self.emu.hook_add(UC_HOOK_CODE, self.whitelist_hook)
        else:
            self.emu.hook_add(UC_HOOK_CODE, self.blacklist_hook)

    def syscall_hook(self, uc, user_data):
        rax = uc.reg_read(UC_X86_REG_RAX)
        rdi = uc.reg_read(UC_X86_REG_RDI)
        if rax == 0x3C:
            uc.emu_stop()
        else:
            print("Error: syscall %d not supported" % rax)

    def get_size_of_insn_at(self, idx):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i, insn in enumerate(
            md.disasm(self.asm, self.BASE_ADDR + self.CODE_OFFSET)
        ):
            if i == idx:
                return insn.size

class ASMLevel1(ASMBase):
    """
    Small Register Access
    """

    def __init__(self, asm=None, should_debug=False):
        super().__init__(asm=asm, registers_use=True, dynamic_values=True, should_debug=should_debug)
        self.val_rdi = random.randint(0x0101, 0xFFFF)
        self.val_rsi = random.randint(0x01000001, 0xFFFFFFFF)

    def print_level_text(self):
        print(
            "Using only the following instruction(s):")
        print(colorama.Fore.RED + "mov")
        print(colorama.Fore.WHITE+
            "Please compute the following:\n"
            "rax = rdi modulo 256\n"
            "rbx = rsi module 65536"
        )

        print(
            "We will now set the following in preparation for your code:\n"
            f"rdi = {hex(self.val_rdi)}\n"
            f"rsi = {hex(self.val_rsi)}\n\n"
        )

    def trace(self):
        self.add_emu_inst_filter(["mov"], True)
        try:
            self.emu.reg_write(UC_X86_REG_RDI, self.val_rdi)
            self.emu.reg_write(UC_X86_REG_RSI, self.val_rsi)
            self.emu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(self.asm))
        except UcError as e:
            print("ERROR: %s" % e)

        if self.emu_err:
            print(self.emu_err)
            return False

        correct = (self.val_rdi % 256) == self.emu.reg_read(UC_X86_REG_RAX)
        correct &= (self.val_rsi % 65536) == self.emu.reg_read(UC_X86_REG_RBX)
        return correct

class ASMLevel2(ASMBase):
    """
    Logic gates as a mov (bit logic)
    """

    def __init__(self, asm=None, should_debug=False):
        super().__init__(
            asm=asm, dynamic_values=True, registers_use=True, bit_logic=True, should_debug=should_debug
        )
        self.val_rdi = random.randint(0x55AA55AA55AA55AA, 0x99BB99BB99BB99BB)
        self.val_rsi = random.randint(0x55AA55AA55AA55AA, 0x99BB99BB99BB99BB)

    def print_level_text(self):
    
        print(
            "Without using the following instructions:")
        print(
            colorama.Fore.RED+"mov, xchg")
        print(colorama.Fore.WHITE+
            "Please perform the following:\n"
            "rax = rdi AND rsi\n"
            "i.e. Set rax to the value of (rdi AND rsi)\n"
        )

        print(
            "We will now set the following in preparation for your code:\n"
            f"rdi = {hex(self.val_rdi)}\n"
            f"rsi = {hex(self.val_rsi)}\n\n"
        )

    def trace(self):
        self.add_emu_inst_filter(["mov", "xchg"], False)
        try:
            self.emu.reg_write(UC_X86_REG_RDI, self.val_rdi)
            self.emu.reg_write(UC_X86_REG_RSI, self.val_rsi)

            self.emu.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)
            self.emu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(self.asm))
        except UcError as e:
            print("ERROR: %s" % e)

        if self.emu_err:
            print(self.emu_err)
            return False

        target = self.val_rdi & self.val_rsi
        return target == self.emu.reg_read(UC_X86_REG_RAX)

class ASMLevel3(ASMBase):
    """
    Reading specific sizes from addresses
    """

    def __init__(self, asm=None, should_debug=False):
        super().__init__(asm=asm, dynamic_values=True, memory_use=True, should_debug=should_debug)
        self.val = random.randint(1000000, 2000000)

    def print_level_text(self):
        print(
            "Please perform the following:\n"
            "1) Set rax to the byte at 0x404000\n"
            "2) Set rbx to the word at 0x404000\n"
            "3) Set rcx to the double word at 0x404000\n"
            "4) Set rdx to the quad word at 0x404000\n"
        )

        print(
            "We will now set the following in preparation for your code:\n"
            f"[0x404000] = {hex(self.val)}\n\n"
        )

    def trace(self):
        correct = False
        try:
            self.emu.mem_write(self.DATA_ADDR, struct.pack("<Q", self.val))
            self.emu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(self.asm))
        except UcError as e:
            print("ERROR: %s" % e)
            return correct

        try:
            target = struct.unpack("B", self.emu.mem_read(self.DATA_ADDR, 1))[0]
            correct = target == self.emu.reg_read(UC_X86_REG_RAX)

            target = struct.unpack("<H", self.emu.mem_read(self.DATA_ADDR, 2))[0]
            correct &= target == self.emu.reg_read(UC_X86_REG_RBX)

            target = struct.unpack("<L", self.emu.mem_read(self.DATA_ADDR, 4))[0]
            correct &= target == self.emu.reg_read(UC_X86_REG_RCX)

            target = struct.unpack("<Q", self.emu.mem_read(self.DATA_ADDR, 8))[0]
            correct &= target == self.emu.reg_read(UC_X86_REG_RDX)
        except Exception as e:
            print("ERROR: %s" % e)
        return correct


class ASMLevel4(ASMBase):
    """
    Write static values to dynamic memory (of different size)
    """

    def __init__(self, asm=None, should_debug=False):
        super().__init__(asm=asm, dynamic_values=True, memory_use=True, should_debug=should_debug)
        self.mem_addr_1 = self.DATA_ADDR + (8 * random.randint(0, 250))
        self.mem_addr_2 = self.DATA_ADDR + (8 * random.randint(250, 500))
        self.mem_val_1 = 0xDEADBEEF00001337
        self.mem_val_2 = 0x000000C0FFEE0000

    def print_level_text(self):
        print(
            "It is worth noting, as you may have noticed, that values are stored in reverse order of how we\n"
            "represent them. As an example, say:\n"
            "[0x1330] = 0x00000000deadc0de\n"
            "If you examined how it actually looked in memory, you would see:\n"
            "[0x1330] = 0xde 0xc0 0xad 0xde 0x00 0x00 0x00 0x00\n"
            "This format of storing things in 'reverse' is intentional in x86, and its called Little Endian.\n"
        )

        print(
            "For this challenge we will give you two addresses created dynamically each run. The first address\n"
            "will be placed in rdi. The second will be placed in rsi.\n"
            "Using the earlier mentioned info, perform the following:\n"
            f"1. set [rdi] = {'0x{0:0{1}X}'.format(self.mem_val_1,16)}\n"
            f"2. set [rsi] = {'0x{0:0{1}X}'.format(self.mem_val_2,16)}\n"
            "Hint: it may require some tricks to assign a big constant to a dereferenced register. Try setting\n"
            "a register to the constant than assigning that register to the derefed register.\n"
        )

        print(
            "We will now set the following in preparation for your code:\n"
            f"[{hex(self.mem_addr_1)}] = 0xffffffffffffffff\n"
            f"[{hex(self.mem_addr_2)}] = 0xffffffffffffffff\n"
            f"rdi = {hex(self.mem_addr_1)}\n"
            f"rsi = {hex(self.mem_addr_2)}\n\n"
        )

    def trace(self):
        try:
            self.emu.mem_write(self.mem_addr_1, b"\xff" * 16)
            self.emu.mem_write(self.mem_addr_2, b"\xff" * 16)

            self.emu.reg_write(UC_X86_REG_RDI, self.mem_addr_1)
            self.emu.reg_write(UC_X86_REG_RSI, self.mem_addr_2)

            self.emu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(self.asm))
        except UcError as e:
            print("ERROR: %s" % e)
            return False

        return (
            self.emu.mem_read(self.mem_addr_1, 8) == struct.pack("<Q", self.mem_val_1)
        ) and (
            self.emu.mem_read(self.mem_addr_2, 8) == struct.pack("<Q", self.mem_val_2)
        )


class ASMLevel5(ASMBase):
    """
    Swap registers_use
    """

    def __init__(self, asm=None, should_debug=False):
        super().__init__(asm=asm, dynamic_values=True, stack_use=True, should_debug=should_debug)
        self.val_rdi = random.randint(1000000, 1000000000)
        self.val_rsi = random.randint(1000000, 1000000000)

    def print_level_text(self):
        print(
            "In this level we are going to explore the last in first out (LIFO) property of the stack.\n"
        )
        print(
            "Using only following instructions:\n"
            "push, pop\n"
            "Swap values in rdi and rsi.\n"
            "i.e.\n"
            "If to start rdi = 2 and rsi = 5\n"
            "Then to end rdi = 5 and rsi = 2\n"
        )

        print(
            "We will now set the following in preparation for your code:\n"
            f"rdi = {hex(self.val_rdi)}\n"
            f"rsi = {hex(self.val_rsi)}\n\n"
        )

    def trace(self):
        self.add_emu_inst_filter(["push", "pop"], True)
        try:
            self.emu.reg_write(UC_X86_REG_RSI, self.val_rsi)
            self.emu.reg_write(UC_X86_REG_RDI, self.val_rdi)
            self.emu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(self.asm))
        except UcError as e:
            print("ERROR: %s" % e)

        if self.emu_err:
            print(self.emu_err)
            return False

        correct = self.val_rdi == self.emu.reg_read(UC_X86_REG_RSI)
        correct &= self.val_rsi == self.emu.reg_read(UC_X86_REG_RDI)
        return correct


if __name__ == "__main__":
    assert len(sys.argv) == 2
    level_choice = int(sys.argv[1])
    level = globals()[f"ASMLevel{level_choice}"]()
    try:
        level.run()
    except KeyboardInterrupt:
        sys.exit(1)
