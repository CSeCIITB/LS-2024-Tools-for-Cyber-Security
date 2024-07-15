You are given two challenges each consisting of 5 levels.
The two challenges are in the files [chall_1.py](chall_1.py) & [chall_2.py](chall_2.py). These programs accept assmebly as bytes. We have added broiler code that converts assembly to bytes in [broiler_1.py](broiler_1.py) & [broiler_2.py](broiler_2.py), these come in handy while running the challenges.

You have to mention the level(send as a command line argument to the chall files) in broiler code at line 9 (initially set to 1) and then write your assembly code at the specified place.
On running the broiler file using `python3 broiler_1.py` or `python broiler_2.py`, you will see the task you need to perform in that level, and this would also run the assembly code which you wrote earlier.

Each level makes you familiar with various functionalities of x86 assembly programming.

## Submission Instruction
You need to create 10 text files of the format `asm_{chall}_{level}.txt`, where chall ∈ [1,2] and level ∈ [1,5]. Save these text files inside a directory named `submission`. Each text file should contain the assembly code for the corresponding level.
