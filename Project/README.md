# The Project

## Part 1: Sudoku Solver

Run the game [sudoku](./sudoku) as:
```bash
chmod +x sudoku # If the file is not marked as executable
./sudoku
```
[ <b>NOTE</b> : The indices, i.e. rows and columns, are zero-indexed (the first element is referred by 0) ] <br>
<br>
You task is to create a program that solves all the presented sudoku puzzles. 
Successfully doing this for the 420 random instances provided by the program will get you the flag.

### Submission Instruction
Create a file `script.py` which solves the challenge. The first line of this file should contain a comment with the flag you obtained.

### Disclaimer:
Note that this project is designed to test your ability to write a Python script that interacts with a binary executable and solves the presented Sudoku puzzles. If you have simply reverse engineered the binary to directly obtain the flag without solving the puzzles, your submission will not be considered.


### Submission Link
Add all files related to your project submission in a public GitHub repository and submit the link to the repo here: https://forms.gle/R3tqnS1WsVgrYyNN7

## Part 2: Brainfuck Interpreter

[Brainfuck](https://en.wikipedia.org/wiki/Brainfuck) is an esoteric programming language, consisting of only eight commands: `>`, `<`, `+`, `-`, `[`, `]`, `.` and `,`. Despite its simplicity, Brainfuck is Turing complete, meaning it can theoretically solve any computational problem given enough time and memory.

In this project, you will implement a simple Brainfuck interpreter in C. This interpreter will read Brainfuck code, execute it, and produce the corresponding output.

To assist you in getting started, a sample template of the Brainfuck interpreter in C can be found [here](./brainfuck.c). Note that using the helper code is not compulsory. Feel free to write the whole interpreter yourself.

### Testing
Your interpreter should take as input a brainfuck program in the following format and print the output to stdout:

```bash
./brainfuck "<program>"
```

**For example**: 

`./brainfuck "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++."` should output `Hello World!` 


### Submission Link
Add all files related to your project submission in a public GitHub repository and submit the link to the repo here: https://forms.gle/KxGbKkbiqf6HCcG47