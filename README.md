# A simple elf injector

- Coded in C, it uses the segmentation padding injection techique, to inject shellcode in an code cave.
- It manipulates the original entry point (OEP), to point to the beginning of the shellcode, and then the shellcode restores the OEP and jump to it.
- It can infect static and dynamic linked Elf files.

Build:
- On your terminal, type: make
- To clean, type: make clean

Run:
- ./injector
- If you want to infectec static ones, use shellcode-static, otherwise use shellcode-dyn.
- After infecting, just run it.

## Dynamic linked example:
- Infecting the ls program.
![Alt text](./testing-dyn.png?raw=true "Infect ls")