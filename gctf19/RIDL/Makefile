all: solve.bin

solve.elf: solve.c
	gcc -m64 -nostdlib -static -Os -mrtm -fno-toplevel-reorder -static -Wno-multichar $< -o $@

solve.bin: solve.elf
	objcopy -Obinary -j .text $< $@


clean:
	rm -f solve.elf solve.bin
