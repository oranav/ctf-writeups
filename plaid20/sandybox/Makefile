all: shellcode.bin


shellcode.bin: shellcode1.bin shellcode2.bin
	cat $^ > shellcode.bin

%.bin: %.asm
	nasm -f bin $< -o $@

clean:
	rm -f *.bin
