# Hardware configuration settings.
MCU = atmega1284p
F_CPU = 20000000
BAUD = 115200

# Secret password default value.
RB_KEY ?= rb_key
UD_KEY ?= ud_key

# Tool aliases.
CC = avr-gcc
STRIP  = avr-strip
OBJCOPY = avr-objcopy
PROGRAMMER = dragon_jtag

# Compiler configurations.
BL_START = 0x1E000
CDEFS = -g3 -ggdb3 -mmcu=${MCU} -DF_CPU=${F_CPU} -DBAUD=${BAUD} -DUD_KEY=${UD_KEY} -DRB_KEY=${RB_KEY}

# Description of CLINKER options:
# 	-Wl,--section-start=.text=0x1E000 -- Offsets the code to the start of the bootloader section
# 	-Wl,-Map,bootloader.map -- Created an additional file that lists the locations in memory of all functions.
CLINKER = -nostartfiles -Wl,--section-start=.text=$(BL_START) -Wl,-Map,bootloader.map
CWARN =  -Wall
COPT = -std=gnu99 -Os -fno-tree-scev-cprop -mcall-prologues \
       -fno-inline-small-functions -fsigned-char

CFLAGS = $(CDEFS) $(CLINKER) $(CWARN) $(COPT)

# Include file paths.
INCLUDES = -I./include -I../avrnacl

# Run clean even when all files have been removed.
.PHONY: clean all strip

all: flash.hex eeprom.hex avrnacl/avrnacl_small/obj/libnacl.a
	@echo  Simple bootloader has been compiled and packaged as intel hex.

uart.o: src/uart.c include/uart.h
	$(CC) $(CFLAGS) $(INCLUDES) -c src/uart.c

sys_startup.o: src/sys_startup.c
	$(CC) $(CFLAGS) $(INCLUDES) -c src/sys_startup.c

bootloader.o: src/bootloader.c include/uart.h
	$(CC) $(CFLAGS) $(INCLUDES) -c src/bootloader.c

avrnacl/avrnacl_small/obj/libnacl.a: $(wildcard avrnacl/*)
	make -C avrnacl

bootloader_dbg.elf: uart.o sys_startup.o bootloader.o avrnacl/avrnacl_small/obj/libnacl.a
	$(CC) $(CFLAGS) $(INCLUDES) -o bootloader_dbg.elf $^

strip: bootloader_dbg.elf
	$(STRIP) bootloader_dbg.elf -o bootloader.elf

flash.hex: strip
	$(OBJCOPY) -R .eeprom -O ihex bootloader.elf flash.hex

eeprom.hex: strip
	$(OBJCOPY) -j .eeprom --set-section-flags=.eeprom="alloc,load" --change-section-lma .eeprom=0 -O ihex bootloader.elf eeprom.hex
	avr-size flash.hex

test: flash.hex eeprom.hex
	avrdude -F -P usb -p m1284p -c $(PROGRAMMER)  -u -U flash:w:flash.hex:i \
							-U eeprom:w:eeprom.hex:i \
							-U lfuse:w:lfuse.hex:i \
							-U hfuse:w:hfuse.hex:i \
							-U efuse:w:efuse.hex:i


flash: flash.hex eeprom.hex
	avrdude -F -P usb -p m1284p -c $(PROGRAMMER)  -u -U flash:w:flash.hex:i \
							-U eeprom:w:eeprom.hex:i \
							-U lfuse:w:lfuse.hex:i \
							-U hfuse:w:hfuse.hex:i \
							-U efuse:w:efuse.hex:i \
							-U lock:w:lock.hex:i

debug: flash.hex eeprom.hex
		# Launch avarice: a tool that creates a debug server for the AVR and Dragon
		avarice -R -g --jtag-bitrate 250khz :4242 &
		# Launch the avr debugger avr-gdb. The configuation for this tool is included
		# in .gdbinit
		avr-gdb -tui bootloader_dbg.elf

clean:
	$(RM) -v *.hex *.o *.elf $(MAIN)
	$(MAKE) -C avrnacl clean
