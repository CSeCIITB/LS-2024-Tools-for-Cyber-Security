from pwn import *

context.arch = "amd64"
context.log_level= "INFO"
context.encoding = "latin"
warnings.simplefilter("ignore")

chall = os.path.basename(__file__).split('_')[1].split('.')[0]
level = 1  #mention level: [1,5]

""""write your assembly code below"""
assembly = """
mov rax, 69
mov rbx, 420
xor rax,rax
nop
"""

with process(['python3', f'chall_{chall}.py', str(level)]) as p:
    info(p.readrepeat(1))
    p.send(asm(assembly))
    info(p.readrepeat(1))

