# Bruteforcer

You are given a program `bruteforcer` which can be run using the following commands while in this directory
```bash
chmod +x bruteforcer #If the file is not marked as executable
./bruteforcer
```
The program prompts for an input when executed and will print out the flag on giving the correct password.

Also included is a `wordlist.txt` consisting of a list of around 5 million passwords; one of which is the above mentioned correct password. 
Your task is to write a script that automatically finds this correct password.
Checking each word sequentially in the provided wordlist, however, will take a lot of time due to the huge size of the wordlist.

This is where you can use the information on whether the password you provide is larger or smaller
([lexicographically](https://en.wikipedia.org/wiki/Lexicographic_order)) than the correct password. This information can be used to perform
a [binary search](https://www.khanacademy.org/computing/computer-science/algorithms/binary-search/a/binary-search) over the wordlist and quickly find the answer.

Flag format: flag{...}
