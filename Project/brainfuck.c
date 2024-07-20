#include <stdio.h>
#include <stdlib.h>

#define TAPE_SIZE 30000

void execute_brainfuck(const char *code) {
    char tape[TAPE_SIZE] = {0};
    char *ptr = tape;
    const char *pc = code;

    while (*pc) {
        switch (*pc) {
            case '>':
                // TODO
                break;
            case '<':
                // TODO
                break;
            case '+':
                // TODO
                break;
            case '-':
                // TODO
                break;
            case '.':
                // TODO
                break;
            case ',':
                // TODO
                break;
            case '[':
                // TODO
                break;
            case ']':
                // TODO
                break;
            default:
				// TODO
                break;
        }
        ++pc;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s \"<brainfuck code>\"\n", argv[0]);
        return 1;
    }

    execute_brainfuck(argv[1]);

    return 0;
}
