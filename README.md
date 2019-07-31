## Worcester Polytechnic Institute Design Documentation for 2017 MITRE eCTF Competition

Written by Jacob Grycel


# System Overview:
The secure bootloader system operates on a sequential communication process between a host and target device (the ATmega1284P microcontroller). For all firmware updates to the bootloader and memory readback requests from the host system, each data packet from the host is validated before the data is accepted as being authentic by the bootloader.

# Host Tools:
**Bootloader Build Tool:** bl_build generates secret encryption keys for performing firmware updates and readback requests. All secret keys are stored in an output file, secret_build_output.txt, which is later referenced by the bootloader configure tool. Additionally, this tool generates HEX files for flash, eeprom, low, high, and extended fuse bits, and lock bits. These HEX files should be programmed into the target device. Programming the bootloader to the target device will initialize it to be in a “waiting for configuration” state.

Command line arguments: none

**Bootloader Configure Tool:** bl_configure communicates with the target device over a serial communication port, and sends a configure message to take the bootloader out of its configure state and into normal functionality. All values stored in secret_build_output.txt are transferred to secret_configure_output.txt.

Command line arguments: --port (usb port for serial communications)

**Firmware Protection Tool:** fw_protect creates a protected and formatted firmware image from an input firmware file. The input firmware is segmented in 256 byte blocks contained in 262 byte frames, and packed into a data packet along with the size of the valid data in the packet, the frame number, firmware version, and a release message indicator. If a frame contains the release message this indicator is set.
Data is protected using the xSalsa20 stream cipher with a 32 byte update key, and 24 byte nonce. Each 262 byte frame is encrypted, and combined with the nonce and plaintext byte, into a message which is hashed using SHA 512. The output is then combined with the key again and hashed with SHA512 to produce a MAC (Message Authentication Code).

Command line arguments: --infile (firmware image to protect); --outfile (file to store protected firmware in); -- version 		(firmware version number); --message (release message to append to the firmware)

**Firmware Update Tool:** fw_update communicates with the target device bootloader to send a new firmware image for installation on the device. The protected firmware image is sent to the bootloader in reverse order, sending the highest-numbered frame first, and the lowest-numbered frame last. For each frame the tool sends the MAC for the frame, the frame data, and the nonce used to encrypt that frame. After each frame send the updater waits for an OK from the bootloader to continue.

Command line arguments: --firmware (protected firmware image to send) –port (serial port to communicate over)

**Memory Readback Tool:** readback communicates with the target device bootloader to request for a readout of a specified memory region in FLASH. A message is created by appending a 32 byte readback key, 24 byte nonce, and the memory start address and segment length, which is then hashed using SHA 512. The output of this hash is appended with the key again and hashed with SHA 512, yielding a MAC for the readback request. The MAC is sent to the bootloader along with the data request. Once the bootloader confirms the request is authentic, the memory section will be read back to the host.

Command line arguments: --address (start address for readback) –num-bytes (the number of bytes of memory to read after the start 	address) –port (serial port to communicate over) –datafile (optional output file to write the memory segment to)


# Bootloader:
**Firmware Updates:** The embedded bootloader supports firmware updates in the form of 256 byte frames, each with 6 bytes of additional data for addressing and version verification. The bootloader writes firmware images to FLASH memory in reverse order, with the release message being written first at an appropriate data address, and the start address of each successive frame being installed a full PAGESIZE section earlier in memory. The last frame to be written is at address 0 to protect against incomplete firmware images being installed. Each frame is validated by generating a MAC on board from the frame data and update key. If the MAC fails verification, installation is aborted.
The bootloader checks each that each frame has a valid version number to prohibit the installation of older firmware versions.
Firmware installation will be canceled if the bootloader detects one of these inconsistencies:
* Old version
* Invalid address location
* Invalid MAC

**Memory Readback:** A readback request from the host is validated by generating a MAC from the readback request, unique nonce, and readback key. Readback will fail if an invalid MAC is detected

# Primitives:
This system utilizes the secure Networking and Cryptography Library (NaCl), with the host tools using the python port (PyNaCl) of the library, and the bootloader using the avr port (avrnacl) of the library. The avrnacl-small subset of the AVR port of NaCl is used to minimize space used by cryptographic source code. The bootloader and host systems use the following cryptographic primitives for security:

* SHA 512
* xSalsa20 stream cipher