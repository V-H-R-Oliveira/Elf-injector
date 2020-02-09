all:
	gcc -Wall -Werror -O3 -s -o injector main.c
	gcc -static -O3 -s -o testing-static example.c
	gcc -O3 -s -o testing-dyn example.c	
	nasm -f elf64 shellcode.nasm && ld -s -o shellcode-static shellcode.o && rm shellcode.o
	nasm -f elf64 shellcode2.nasm && ld -s -o shellcode-dyn shellcode2.o && rm shellcode2.o
clean:
	rm injector shellcode-dyn shellcode-static testing-dyn testing-static
