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
    If statements
    """

    def __init__(self, asm=None, should_debug=False):
        super().__init__(asm=asm, multi_test=True, ip_control=True, should_debug=should_debug)
        self.mem_addr = self.DATA_ADDR + (8 * random.randint(0, 250))

    def print_level_text(self):

        print(
            colorama.Fore.RED+
            "if [x] is 0x7f454c46:\n"
            "   y = [x+4] + [x+8] + [x+12]\n"
            "else if [x] is 0x00005A4D:\n"
            "   y = [x+4] - [x+8] - [x+12]\n"
            "else:\n"
            "   y = [x+4] * [x+8] * [x+12]\n\n"
            +colorama.Fore.WHITE+
            "where:\n"
            "x = rdi, y = rax. Assume each dereferenced value is a signed dword. This means the values can start as"
            "a negative value at each memory position.\n"
            "A valid solution will use the following at least once:\n"
            "jmp (any variant), cmp\n"
        )

        print(
            "We will now run multiple tests on your code, here is an example run:\n"
            f"- (data) [{hex(self.DATA_ADDR)}] = {{4 random dwords]}}\n"
            f"- rdi = {hex(self.DATA_ADDR)}\n\n"
        )

        pass

    def debug(self):
        mem_loc = self.DATA_ADDR + random.randint(0x0, 0x100)
        header_choices = [0x7F454C46, 0x00005A4D, 0x00000000]
        mem_vals = [random.choice(header_choices)]
        mem_vals += [random.randint(-(2 ** 16), 2 ** 16) for _ in range(3)]
        self.unit_test_user_code(mem_loc, mem_vals, debug=True)

    def unit_test_user_code(self, mem_loc, mem_vals, debug=False):
        if debug:
            print("Entering debugging mode!")
        else:
            self.create_emu()
        try:
            self.emu.mem_write(mem_loc, struct.pack("<iiii", *mem_vals))
            self.emu.reg_write(UC_X86_REG_RDI, mem_loc)
            self.emu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(self.asm))
        except UcError as e:
            print("ERROR: %s" % e)
            return False

        user_out = self.emu.reg_read(UC_X86_REG_RAX)

        if mem_vals[0] == 0x7F454C46:
            correct_out = sum(mem_vals[1:]) & 0xFFFFFFFF
        elif mem_vals[0] == 0x00005A4D:
            correct_out = (mem_vals[1] - mem_vals[2] - mem_vals[3]) & 0xFFFFFFFF
        else:
            correct_out = (mem_vals[1] * mem_vals[2] * mem_vals[3]) & 0xFFFFFFFF

        return user_out == correct_out

    def trace(self):
        if self.should_debug:
            self.debug()

        passes = True
        mem_loc = self.DATA_ADDR + random.randint(0x0, 0x100)
        header_choices = [0x7F454C46, 0x00005A4D, 0x00000000]
        for _ in range(100):
            mem_vals = [random.choice(header_choices)]
            mem_vals += [random.randint(-(2 ** 16), 2 ** 16) for _ in range(3)]
            passes &= self.unit_test_user_code(mem_loc, mem_vals)

        return passes


class ASMLevel2(ASMBase):
    def __init__(self, asm=None, should_debug=False):
        super().__init__(asm=asm, multi_test=True, ip_control=True, should_debug=should_debug)
        self.exit_key = random.randint(0, 0xFFFFFFFFFFFFFFF8)
        self.libs = [
            pwnlib.asm.asm(f"mov rdi, {self.exit_key + i}; mov rax, 0x3c; syscall")
            for i in range(5)
        ]
        self.insn_uses = defaultdict(int)

        self.jmp_locs = self.get_random_jmp_locs(5)
        self.table_loc = self.DATA_ADDR + random.randint(0, 1024)

    def print_level_text(self):
        print_many_lines(
            f"""
            The last set of jump types is the indirect jump, which is often used for switch statements in the
            real world. Switch statements are a special case of if-statements that use only numbers to
            determine where the control flow will go. Here is an example:
            switch(number):
                0: jmp do_thing_0
                1: jmp do_thing_1
                2: jmp do_thing_2
                default: jmp do_default_thing
            The switch in this example is working on `number`, which can either be 0, 1, or 2. In the case that
            `number` is not one of those numbers, default triggers. You can consider this a reduced else-if
            type structure.
            In x86, you are already used to using numbers, so it should be no suprise that you can make if
            statements based on something being an exact number. In addition, if you know the range of the numbers,
            a switch statement works very well. Take for instance the existence of a jump table. A jump table
            is a contiguous section of memory that holds addresses of places to jump. In the above example, the
            jump table could look like:
            [0x1337] = address of do_thing_0
            [0x1337+0x8] = address of do_thing_1
            [0x1337+0x10] = address of do_thing_2
            [0x1337+0x18] = address of do_default_thing
            Using the jump table, we can greatly reduce the amount of cmps we use. Now all we need to check
            is if `number` is greater than 2. If it is, always do:
            jmp [0x1337+0x18]
            Otherwise:
            jmp [jump_table_address + number * 8]
            Using the above knowledge, implement the following logic:
            if rdi is 0:
                jmp {hex(self.jmp_locs[0])}
            else if rdi is 1:
                jmp {hex(self.jmp_locs[1])}
            else if rdi is 2:
                jmp {hex(self.jmp_locs[2])}
            else if rdi is 3:
                jmp {hex(self.jmp_locs[3])}
            else:
                jmp {hex(self.jmp_locs[4])}
            Please do the above with the following constraints:
            - assume rdi will NOT be negative
            - use no more than 1 cmp instruction
            - use no more than 3 jumps (of any variant)
            - we will provide you with the number to 'switch' on in rdi.
            - we will provide you with a jump table base address in rsi.

            Here is an example table:
                [{hex(self.table_loc + 0)}] = {hex(self.jmp_locs[0])} (addrs will change)
                [{hex(self.table_loc + 8)}] = {hex(self.jmp_locs[1])}
                [{hex(self.table_loc + 16)}] = {hex(self.jmp_locs[2])}
                [{hex(self.table_loc + 24)}] = {hex(self.jmp_locs[3])}
                [{hex(self.table_loc + 32)}] = {hex(self.jmp_locs[4])}
            """
        )

    def get_random_jmp_locs(self, amt) -> List[int]:
        last_addr = self.LIB_ADDR
        rand_jmps = list()
        for i in range(amt):
            chosen_addr = random.randint(last_addr, last_addr + 100)
            rand_jmps.append(chosen_addr)
            last_addr = chosen_addr + len(self.libs[0])

        return rand_jmps

    def count_insn_uses(self, uc, address, size, user_data):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        i = next(md.disasm(uc.mem_read(address, size), address))

        if str(i.mnemonic).startswith("j"):
            self.insn_uses["j*"] += 1
        else:
            self.insn_uses[str(i.mnemonic)] += 1

    def debug(self):
        switch_num = random.randint(0, 5)
        table_loc = self.DATA_ADDR + random.randint(0, 1024)
        jmp_locs = self.get_random_jmp_locs(5)
        self.unit_test_user_code(switch_num, table_loc, jmp_locs, debug=True)

    def unit_test_user_code(self, switch_num, table_loc, jmp_locs, debug=False):
        if debug:
            print("Entering debugging mode!")
        else:
            self.create_emu()
        self.insn_uses = defaultdict(int)
        try:
            self.emu.mem_write(table_loc, struct.pack("<QQQQQ", *jmp_locs))

            for i in range(len(jmp_locs)):
                self.emu.mem_write(jmp_locs[i], self.libs[i])

            self.emu.reg_write(UC_X86_REG_RDI, switch_num)
            self.emu.reg_write(UC_X86_REG_RSI, table_loc)

            self.emu.hook_add(
                UC_HOOK_INSN, self.syscall_hook, None, 1, 0, UC_X86_INS_SYSCALL
            )

            self.emu.hook_add(
                UC_HOOK_CODE,
                self.count_insn_uses,
                None,
                self.BASE_ADDR,
                self.BASE_ADDR + 0x5000,
            )

            self.emu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(self.asm))
        except UcError as e:
            print("ERROR: %s" % e)
            print(f"RIP: {hex(self.emu.reg_read(UC_X86_REG_RIP))}")

        if self.insn_uses["j*"] > 3 or self.insn_uses["cmp"] > 1:
            print("Too many restricted instructions used!")
            return False

        exit_offset = switch_num if switch_num <= 3 else 4
        correct_exit_key = self.exit_key + exit_offset

        return correct_exit_key == self.emu.reg_read(UC_X86_REG_RDI)

    def trace(self):
        if self.should_debug:
            self.debug()

        for _ in range(100):
            switch_num = random.randint(0, 5)
            table_loc = self.DATA_ADDR + random.randint(0, 1024)
            jmp_locs = self.get_random_jmp_locs(5)
            res = self.unit_test_user_code(switch_num, table_loc, jmp_locs)
            if not res:
                return False

        return True


class ASMLevel3(ASMBase):
    """
    Implement strlen
    """

    def __init__(self, asm=None, should_debug=False):
        super().__init__(asm=asm, multi_test=True, ip_control=True, should_debug=should_debug)
        self.str_addr = self.DATA_ADDR + (random.randint(10, 100) * 8)

    def print_level_text(self):
        print_many_lines(
            f"""
            what happens when you want to iterate until you meet a condition? A second loop
            structure exists called the while-loop to fill this demand. In the while-loop you iterate until a
            condition is met. As an example, say we had a location in memory with adjacent numbers and we wanted
            to get the average of all the numbers until we find one bigger or equal to 0xff:
            average = 0
            i = 0
            while x[i] < 0xff:
                average += x[i]
                i += 1
            average /= i

            Using the above knowledge, please perform the following:
            Count the consecutive non-zero bytes in a contiguous region of memory, where:
            rdi = memory address of the 1st byte
            rax = number of consecutive non-zero bytes
            Additionally, if rdi = 0, then set rax = 0 (we will check)!
            An example test-case, let:
            rdi = 0x1000
            [0x1000] = 0x41
            [0x1001] = 0x42
            [0x1002] = 0x43
            [0x1003] = 0x00
            then: rax = 3 should be set

            We will now run multiple tests on your code, here is an example run:
            - (data) [{hex(self.DATA_ADDR)}] = {{10 random bytes}},
            - rdi = {hex(self.DATA_ADDR)}

            """
        )

    def debug(self):
        str_len = random.randint(1, 1000)
        tst_str = [ord(random.choice(string.ascii_letters)) for _ in range(str_len)]
        tst_str.append(0)
        self.unit_test_user_code(self.str_addr, tst_str, debug=True)

    def unit_test_user_code(self, addr, tst_str, debug=False):
        if debug:
            print("Entering debugging mode!")
        else:
            self.create_emu()
        try:
            self.emu.reg_write(UC_X86_REG_RDI, addr)
            if addr != 0:
                self.emu.mem_write(addr, struct.pack(f"{'B'*(len(tst_str))}", *tst_str))
            self.emu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(self.asm))
        except UcError as e:
            print("ERROR: %s" % e)

        if addr != 0:
            target = len(tst_str) - 1
        else:
            target = 0

        correct = target == self.emu.reg_read(UC_X86_REG_RAX)
        if not correct:
            print_many_lines(
            f"""
            [!] ------------------------- [!]
            Failed test check:
            Input:
            list address: {hex(addr)}
            list values: {[hex(i) for i in tst_str]}

            Correct output:
            rax = {hex(target)}
            
            Your output:
            rax = {hex(self.emu.reg_read(UC_X86_REG_RAX))}
            [!] ------------------------- [!]
            """
            )

        return correct

    def trace(self):
        if self.should_debug:
            self.debug()

        correct = True

        correct &= self.unit_test_user_code(0x0, b"")

        correct &= self.unit_test_user_code(self.str_addr, b"\x00")

        for _ in range(100):
            str_len = random.randint(1, 1000)
            tst_str = [ord(random.choice(string.ascii_letters)) for _ in range(str_len)]
            tst_str.append(0)
            correct &= self.unit_test_user_code(self.str_addr, tst_str)
            if not correct:
                return False

        return correct


class ASMLevel4(ASMBase):
    """
    strchr as function
    """

    def __init__(self, asm=None, should_debug=False):
        super().__init__(asm=asm, multi_test=True, functions=True, should_debug=should_debug)
        self.str_addr = self.DATA_ADDR + (random.randint(10, 100) * 8)
        self.foo = pwnlib.asm.asm(
            f"""
            mov rax, 0x20
            add rax, rdi
            ret
            """
        )
        self.harness = pwnlib.asm.asm(
            f"""
            mov rax, 0x400000;
            call rax;
            """
        )

    def print_level_text(self):
        print_many_lines(
            f"""
            In previous levels you implemented a while loop to count the number of
            consecutive non-zero bytes in a contiguous region of memory. In this level
            you will be provided with a contiguous region of memory again and will loop
            over each performing a conditional operation till a zero byte is reached.
            All of which will be contained in a function!

            A function is a callable segment of code that does not destory control flow.
            Functions use the instructions "call" and "ret".

            The "call" instruction pushes the memory address of the next instruction onto
            the stack and then jumps to the value stored in the first argument.

            Let's use the following instructions as an example:
            0x1021 mov rax, 0x400000
            0x1028 call rax
            0x102a mov [rsi], rax

            1. call pushes 0x102a, the address of the next instruction, onto the stack.
            2. call jumps to 0x400000, the value stored in rax.
            The "ret" instruction is the opposite of "call". ret pops the top value off of
            the stack and jumps to it.
            Let's use the following instructions and stack as an example:
                                        Stack ADDR  VALUE
            0x103f mov rax, rdx         RSP + 0x8   0xdeadbeef
            0x1042 ret                  RSP + 0x0   0x0000102a
            ret will jump to 0x102a
            Please implement the following logic:
            str_lower(src_addr):
                rax = 0
                if src_addr != 0:
                    while [src_addr] != 0x0:
                        if [src_addr] <= 90:
                            [src_addr] = foo([src_addr])
                            rax += 1
                        src_addr += 1
            foo is provided at {hex(self.LIB_ADDR)}. foo takes a single argument as a value

            We will now run multiple tests on your code, here is an example run:
            - (data) [{hex(self.DATA_ADDR)}] = {{10 random bytes}},
            - rdi = {hex(self.DATA_ADDR)}

            """
        )

    def create_string_and_c(self, len):
        rand_str = [ord(random.choice(string.ascii_letters)) for _ in range(len)]
        rand_str.append(0)
        return rand_str

    def debug(self):
        len = random.randint(1, 1000)
        tst_str = self.create_string_and_c(len)
        self.unit_test_user_code(self.str_addr, tst_str, debug=True)

    def unit_test_user_code(self, addr, tst_str, debug=False):
        if debug:
            print("Now entering debug mode!")
        else:
            self.create_emu()

        try:
            self.emu.mem_write(self.LIB_ADDR, self.foo)
            self.emu.mem_write(self.LIB_ADDR + 0x100, self.harness)
            self.emu.reg_write(UC_X86_REG_RDI, addr)
            if addr != 0:
                self.emu.mem_write(addr, struct.pack(f"{'B'*(len(tst_str))}", *tst_str))
            self.emu.emu_start(
                self.LIB_ADDR + 0x100, self.LIB_ADDR + 0x100 + len(self.harness)
            )
        except UcError as e:
            print("ERROR: %s" % e)
            print(f"RIP: {hex(self.emu.reg_read(UC_X86_REG_RIP))}")
            return False

        if addr == 0:
            correct = 0 == self.emu.reg_read(UC_X86_REG_RAX)
            if not correct:
                print(f"Failed test check: given address was 0, your rax: {self.emu.reg_read(UC_X86_REG_RAX)}.")
            return correct
        else:
            target = [(c + 0x20) if chr(c).isupper() else c for c in tst_str]
            target = struct.pack(f"{'B'*(len(target))}", *target)
            target = bytearray(target)
            correct = target == self.emu.mem_read(addr, len(tst_str))
            correct_len = len([c for c in tst_str if chr(c).isupper()])

            correct &= correct_len == self.emu.reg_read(UC_X86_REG_RAX)

        if not correct:
            print_many_lines(
            f"""
            [!] ------------------------- [!]
            Failed test check:
            Input:
            list address: {hex(addr)}
            list values: {[hex(i) for i in tst_str]}

            Correct output:
            list: {[hex(i) for i in target]}
            rax = {hex(correct_len)}

            Your output
            list: {[hex(i) for i in self.emu.mem_read(addr, len(tst_str))]}
            rax = {hex(self.emu.reg_read(UC_X86_REG_RAX))}
            [!] ------------------------- [!]
            """
            )

        return correct

    def trace(self):
        if self.should_debug:
            self.debug()

        res = self.unit_test_user_code(0x0, [])
        if not res:
            return False

        res = self.unit_test_user_code(self.str_addr, [0])
        if not res:
            return False

        for _ in range(100):
            len = random.randint(1, 1000)
            tst_str = self.create_string_and_c(len)
            rv = self.unit_test_user_code(self.str_addr, tst_str)
            if not rv:
                return False

        return True


class ASMLevel5(ASMBase):
    def __init__(self, asm=None, should_debug=False):
        super().__init__(asm=asm, multi_test=True, functions=True, should_debug=should_debug)

        self.harness = pwnlib.asm.asm(
            f"""
            mov rax, {hex(self.BASE_ADDR)};
            call rax
            """
        )

    def print_level_text(self):
        print_many_lines(
            """
            In the previous level, you learned how to make your first function and how to call other functions. Now
            we will work with functions that have a function stack frame. A function stack frame is a set of
            pointers and values pushed onto the stack to save things for later use and allocate space on the stack
            for function variables.
            First, let's talk about the special register rbp, the Stack Base Pointer. The rbp register is used to tell
            where our stack frame first started. As an example, say we want to construct some list (a contigous space
            of memory) that is only used in our function. The list is 5 elements long, each element is a dword.
            A list of 5 elements would already take 5 registers, so instead, we can make pace on the stack! The
            assembly w    be running your code in a variety of random ways to verify that the logic is robust enough toould look like:
            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            ; setup the base of the stack as the current top
            mov rbp, rsp
            ; move the st    be running your code in a variety of random ways to verify that the logic is robust enough toack 0x14 bytes (5 * 4) down
            ; acts as an allocation
            sub rsp, 0x14
            ; assign list[2] = 1337
            mov eax, 1337
            mov [rbp-0x8], eax
            ; do more operations on theyou list ...
            ; restore the allocated space
            mov rsp, rbp
            ret
            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            Notice how rbp is always used to restore the stack to where it originally was. If we don't restore
            the stack after use, we will eventually run out TM. In addition, notice how we subtracted from rsp
            since the stack grows down. To make it have more space, we subtract the space we need. The ret
            and call still works the same. It is assumed that you will never pass a stack address across functions,
            since, as you can see from the above use, the stack can be overwritten by anyone at any time.
            Once, again, please make function(s) that implements the following:
            most_common_byte(src_addr, size):
                b = 0
                i = 0
                for i <= size-1:
                    curr_byte = [src_addr + i]
                    [stack_base - curr_byte] += 1
                b = 0
                
                max_freq = 0
                max_freq_byte = 0
                for b <= 0xff:
                    if [stack_base - b] > max_freq:
                        max_freq = [stack_base - b]
                        max_freq_byte = b 
                
                return max_freq_byte
            Assumptions:
            - There will never be more than 0xffff of any byte
            - The size will never be longer than 0xffff
            - The list will have at least one element
            Constraints:
            - You must put the "counting list" on the stack
            - You must restore the stack like in a normal function
            - You cannot modify the data at src_addr
            """
        )

    def debug(self):
        list_offset = random.randint(1, 100)
        list_size = random.randint(10, 40)
        num_base = random.randint(list_size + 1, 0xFE) - list_size
        byte_list = [random.randint(num_base, num_base + (list_size // 2)) for _ in range(list_size)]
        list_addr = self.DATA_ADDR + list_offset
        self.unit_test_user_code(list_addr, byte_list, debug=True)

    def hook_code64(self, uc, address, size, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)
        rax = uc.reg_read(UC_X86_REG_RAX)
        rbx = uc.reg_read(UC_X86_REG_RBX)
        rcx = uc.reg_read(UC_X86_REG_RCX)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        print("\n>>> RIP is 0x%x" % rip)
        print(
            f"rdi: {hex(rdi)}; rsi: {hex(rsi)}; rax: {hex(rax)}; rbx: {hex(rbx)}; rcx: {hex(rcx)}; rdx: {hex(rdx)}"
        )
        print(f"r10: {hex(uc.reg_read(UC_X86_REG_R10))}")

    def unit_test_user_code(self, list_addr, byte_list, debug=False):
        # emulator will be created from debug.py
        if debug:
            print("Now entering debug mode!")
        else:
            self.create_emu()

        try:
            self.emu.mem_write(
                list_addr, struct.pack(f"{'B' * (len(byte_list))}", *byte_list)
            )

            self.set_rsp(self.get_rsp(-0x100))
            self.emu.mem_write(
                self.get_rsp(), struct.pack(f"<{'B' * 0x100}", *([0] * 0x100))
            )
            self.set_rsp(self.RSP_INIT)

            self.emu.reg_write(UC_X86_REG_RDI, list_addr)
            self.emu.reg_write(UC_X86_REG_RSI, len(byte_list))

            self.emu.mem_write(self.LIB_ADDR, self.harness)
            self.emu.emu_start(self.LIB_ADDR, self.LIB_ADDR + len(self.harness))

        except UcError as e:
            print("ERROR: %s" % e)
            print(f"RIP: {hex(self.emu.reg_read(UC_X86_REG_RIP))}")

        stack_fixed = self.emu.reg_read(UC_X86_REG_RSP) == self.RSP_INIT

        list_before_sort = byte_list.copy()
        byte_list.sort()
        most_common_byte = collections.Counter(byte_list).most_common(1)[0][0]
        most_common_correct = most_common_byte == self.emu.reg_read(UC_X86_REG_AL)
        correct = most_common_correct and stack_fixed

        if not correct:
            print_many_lines(
            f"""
            [!] ------------------------- [!]
            Failed test check:
            Input:
            List Address: {hex(list_addr)}
            List Values: {[hex(i) for i in list_before_sort]}
            
            Correct output:
            rax (al) = {hex(most_common_byte)}
            rsp = {hex(self.RSP_INIT)} (same value as start)
            
            Your output
            rax (al) = {hex(self.emu.reg_read(UC_X86_REG_AL))}
            rsp = {hex(self.emu.reg_read(UC_X86_REG_RSP))}
            [!] ------------------------- [!]
            """
            )

        return correct

    def trace(self):
        if self.should_debug:
            self.debug()

        for _ in range(100):
            list_offset = random.randint(1, 100)
            list_size = random.randint(10, 40)
            num_base = random.randint(list_size+1, 0xFE) - list_size
            byte_list = [random.randint(num_base, num_base + (list_size//2)) for _ in range(list_size)]
            if not self.unit_test_user_code(self.DATA_ADDR + list_offset, byte_list):
                return False
        return True


if __name__ == "__main__":
    assert len(sys.argv) == 2
    level_choice = int(sys.argv[1])
    level = globals()[f"ASMLevel{level_choice}"]()
    try:
        level.run()
    except KeyboardInterrupt:
        sys.exit(1)
