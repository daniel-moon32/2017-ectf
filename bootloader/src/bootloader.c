/*
* Secure bootloader
*
* installs firmware updates, executes application
* code, and reads memory segments to legitimate
* user with security priveleges
*/

#include <avr/io.h>
#include <stdint.h>
#include <stdio.h>
#include <util/delay.h>
#include "uart.h"
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include "Data.h"
#include "../avrnacl/avrnacl.h"

// Define UART status messages
#define OK    ((unsigned char)0x00)
#define MAC_ERROR ((unsigned char)0x01)
#define VERSION_ERROR ((unsigned char)0x02)
#define CONFIGURED ((unsigned char)0x43) // ASCII 'C'
// Define readback nonce length
#define RB_NONCE_BYTES (24)
// Define readback request Size
#define RB_REQUEST_SIZE (8)
// Size of firmware frame
#define FRAME_SIZE (SPM_PAGESIZE+6)
// Size of protected frame and unused authenticator
#define PROTECTED_SIZE (FRAME_SIZE+16)
// Constant to indicate if mac generation is for update
#define IS_UPDATE ((unsigned char)1)
// Max array size for mac generation internals
#define MAX_AR_SIZE (crypto_stream_xsalsa20_KEYBYTES+crypto_stream_xsalsa20_NONCEBYTES+PROTECTED_SIZE)

// Access secret keys from built bootloader
const unsigned char update_key[crypto_stream_xsalsa20_KEYBYTES] = UD_KEY;
const unsigned char readback_key[crypto_stream_xsalsa20_KEYBYTES] = RB_KEY;

// Function prototyes
void load_firmware(void);
void write_flash(uint32_t, unsigned char*, uint16_t);
void readback(void);
void boot_firmware(void);
void create_mac(unsigned char*, unsigned char*, uint16_t, unsigned char);
void reset_firmware_info();

// EEPROM variables
uint8_t bl_configured EEMEM = 0;
uint16_t message_bytes EEMEM = 0;
uint16_t fw_bytes EEMEM = 0;
uint16_t fw_version EEMEM = 0;
uint16_t fw_zero EEMEM = 0;

/*
* Bootloader entry point
*
* Wait for configure signal from host
* to assume full functionality
* Choose mode of operation based on
* GPIO ports when configured
*/
int main(void)
{
    // Initialize UART ports
    UART1_init();
    UART1_flush();
    UART0_init();
    // Enable watchdog timer; 2 Second timeout reset
    wdt_enable(WDTO_2S);
    wdt_reset();

    // Proceed to main bootloader functionality
    // only after being configured
    // Configured when 'C' is read on UART1
    while(!eeprom_read_byte(&bl_configured)){
        // Reset to top of bootloader if no configuration signal
        while(!UART1_data_available()) wdt_reset();
        if(UART1_getchar() == CONFIGURED){
            // Set bootloader to be configured
            eeprom_update_byte(&bl_configured, 0x01);
            wdt_reset();
            UART1_putchar(CONFIGURED);
            // Set to version 1
            eeprom_update_word(&fw_version, 1);
            wdt_reset();
        }
    }

    // Configure Port B Pins 2, and 3 as inputs.
    DDRB &= ~((1 << PB2) | (1 << PB3));
    // Enable pullup resistors - give port time to settle.
    PORTB |= (1 << PB2) | (1 << PB3);
    wdt_reset();

    // If jumper is present on Port B pin 2, load new firmware.
    if(!(PINB & (1 << PB2))){
        UART1_putchar('U');
        load_firmware();
    }
    // If jumper is present on Port B pin 3, enter readback mode
    else if(!(PINB & (1 << PB3))){
        UART1_putchar('R');
        readback();
    }
    // Boot firmware if no jumper on pins
    else{
        UART1_putchar('B');
        boot_firmware();
    }
} // main

/*
* Authenticate and load new firmware image
*
* Firmware and release message is written
* to FLASH memory in reverse application order
*/
void load_firmware(void)
{
    // Create containers for authentication and decryption processes
    unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
    unsigned char nonce_frame[crypto_stream_xsalsa20_NONCEBYTES+PROTECTED_SIZE];
    unsigned char mac_in[crypto_hash_sha512_BYTES];
    unsigned char mac[crypto_hash_sha512_BYTES];
    unsigned char ciphertext[FRAME_SIZE+32]; //Extra 32 bytes for zeroes and unused authenticator
    unsigned char plaintext[FRAME_SIZE+32]; //Extra 32 bytes for zeroes
    // Create iteration counters and intermediate storage variables
    unsigned int frames_received = 0;
    unsigned int address = 0;
    uint16_t num_frames = 0;

    // Start the Watchdog Timer; 2 Second timeout reset
    wdt_enable(WDTO_2S);

    // Wait for data on UART1
    while(!UART1_data_available()) __asm__ __volatile__("");
    wdt_reset();

    // Loop until all frames have been received
    // First iteration establishes how many iterations should
    // occur based on first received frame's frame number
    do
    {
        // Read MAC from firmware updater
        // MAC is of length crypto_hash_BYTES (64)
        for(int i = 0; i < crypto_hash_sha512_BYTES; i++){
            mac_in[i] = UART1_getchar();
        }
        wdt_reset();

        // Read encrypted frame from host
        // Frame is of size PROTECTED_SIZE (278)
        for(int i = 0; i < PROTECTED_SIZE; i++){
            ciphertext[16+i] = nonce_frame[crypto_stream_xsalsa20_NONCEBYTES+i] = UART1_getchar();
        } //for
        wdt_reset();

        // Set first 16 bytes of ciphertext to be 0
        // (per the documentation of NACL)
        for(int i = 0; i < 16; i++){
            ciphertext[i] = 0;
        }
        wdt_reset();

        // Get NONCE from host
        // Nonce is of length crypto_stream_xsalsa20_NONCEBYTES (24)
        for(int i = 0; i < crypto_stream_xsalsa20_NONCEBYTES; i++){
            nonce_frame[i] = nonce[i] = UART1_getchar();
        }
        wdt_reset();

        // Create MAC from key, nonce, and frame
        create_mac(mac, nonce_frame, crypto_stream_xsalsa20_NONCEBYTES+PROTECTED_SIZE, IS_UPDATE);
        wdt_reset();

        // Check authenticity of frame sent
        // If not authentic reboot and send error
        if(crypto_verify_32(mac_in, mac) | crypto_verify_32(mac_in+32, mac+32)){
            UART1_putchar(MAC_ERROR);
            while(1) __asm__ __volatile__("");
        }

        // Alert host that MAC has been verified
        UART1_putchar(OK);
        wdt_reset();

        // Decrypt frame using xSalsa 20 stream cipher
        crypto_stream_xsalsa20_xor(plaintext, ciphertext, FRAME_SIZE+32, nonce, update_key);
        // Confirm decryption
        UART1_putchar(OK);

        // Pack frame data into struct
        // Bypass 32 zero padding bytes
        // on plaintext
        struct Frame frame;
        for(int i = 0; i < FRAME_SIZE; i++){
            *((char*)&frame + i) = plaintext[32+i];
        }
        wdt_reset();

        // Evaluation firmware image version number

        // If version is earlier version than current firmware
        // reset to main and generate error signal
        if((frame.version != 0) && (frame.version < eeprom_read_word(&fw_version))){
            UART1_putchar(VERSION_ERROR);
            // wait for watchdog timer to expire
            while(1) __asm__ __volatile__("");
        }
        // If version is zero set fw_zero flag
        // Do not update version numberz
        else if(frame.version == 0){
            eeprom_update_word(&fw_zero, 0x01);
        }
        // If frame version is not zero
        // write new verison number to EEPROM
        else{
            eeprom_update_word(&fw_version, frame.version);
            // Disable firmware 0 flag
            eeprom_update_word(&fw_zero, 0x00);
        }
        wdt_reset();

        // If first iteration of installation,
        // calculate start address of final page
        // and derive number of iterations
        if(frames_received == 0){
            num_frames = frame.frame_no + 1;
            address = frame.frame_no * SPM_PAGESIZE;

            // Reset firmware and message size variables
            eeprom_update_word(&message_bytes, 0);
            eeprom_update_word(&fw_bytes, 0);

            // Erase next page of data to prevent
            // cross-firmware interference
            boot_page_erase_safe(address+SPM_PAGESIZE);
            boot_rww_enable_safe();
        }

        // Write firmware data to flash at current address
        write_flash(address, frame.data, frame.data_size);
        wdt_reset();

        // Update firmware size

        // If frame contains release message, increase size
        // of message in EEPROM
        if(frame.is_message)
            eeprom_update_word(&message_bytes, eeprom_read_word(&message_bytes) + frame.data_size);
        // Update total firmware byte size by full page size
        else
            eeprom_update_word(&fw_bytes, eeprom_read_word(&fw_bytes) + SPM_PAGESIZE);
        // Update next address for frame installation
        address -= SPM_PAGESIZE;

        #if 0
        // Write debugging messages to UART0.
        UART0_putchar('P');
        UART0_putchar(page_address>>8);
        UART0_putchar(page_address);
        #endif
        wdt_reset();
        // Tell host that frame has been processed.
        UART1_putchar(OK);
        // Increment number of frames processed
        frames_received += 1;
        //Loop while frames are pending and installation address is valid
    } while ((frames_received < num_frames) && address >= 0);
} // load_firmware

/*
* Program FLASH memory with new firmware
*/
void write_flash(uint32_t address, unsigned char *data, uint16_t size)
{
    // Erase old firmware data at current address
    boot_page_erase_safe(address);

    // Fill boot page with 2 byte words
    // Write *size* bytes of data
    for(int i = 0; i < size; i += 2){
        uint16_t word = data[i];
        // If size is odd, don't program second byte in word
        word += (i < size-1) ? data[i+1] << 8 : 0;
        boot_page_fill_safe(address+i, word);
    }
    wdt_reset();

    // Write full firmware page to flash
    // Enable read while write access to flash
    boot_page_write_safe(address);
    boot_rww_enable_safe();
} // program_flash

/*
* Read memory back to host
* given a valid readback request
*/
void readback(void)
{
    // Create containers for authenticators
    unsigned char request[RB_REQUEST_SIZE];
    unsigned char nonce_request[RB_NONCE_BYTES+RB_REQUEST_SIZE];
    unsigned char auth[crypto_hash_sha512_BYTES];
    unsigned char auth_in[crypto_hash_sha512_BYTES];
    // Start address for data readback
    uint32_t start_addr;
    // Number of bytes of data to send to host
    uint32_t bytes;

    // Start the Watchdog Timer
    wdt_enable(WDTO_2S);

    // Read connection authenticator from host
    // Authenticator is of length crypto_hash_sha512_BYTES (64)
    for(int i = 0; i < crypto_hash_sha512_BYTES; i++) {
        auth_in[i] = UART1_getchar();
    }
    wdt_reset();

    // Read nonce from host
    // Nonce is of size RB_NONCE_BYTES (24)
    for(int i = 0; i < RB_NONCE_BYTES; i++){
        nonce_request[i] = UART1_getchar();
    }
    wdt_reset();

    // Read request from host
    // Request is of size RB_REQUEST_SIZE (8)
    for(int i = 0; i < RB_REQUEST_SIZE; i++){
        request[i] = nonce_request[RB_NONCE_BYTES+i] = UART1_getchar();
    }
    wdt_reset();

    // Confirm data reception
    UART1_putchar(OK);
    wdt_reset();

    // Create authenticator from key, nonce, and request
    create_mac(auth, nonce_request, RB_NONCE_BYTES+RB_REQUEST_SIZE, !IS_UPDATE);
    wdt_reset();

    // Validate authenticator against correct
    // authenticator generated on board

    // If authenticator is not valid reset
    // back to main and send verification error
	if(crypto_verify_32(auth_in, auth) | crypto_verify_32(auth_in+32, auth+32)) {
		UART1_putchar(MAC_ERROR);
		while(1) __asm__ __volatile__("");
	}

    // Confirm authenticator validation
    UART1_putchar(OK);
	wdt_reset();

    // Construct start address (4 byte value)
    // from request
    start_addr = ((uint32_t)request[0]) << 24;
    start_addr |= ((uint32_t)request[1]) << 16;
    start_addr |= ((uint32_t)request[2]) << 8;
    start_addr |= ((uint32_t)request[3]);

    // Format number of bytes to read (4 byte value)
    // from request
    bytes = ((uint32_t)request[4]) << 24;
    bytes |= ((uint32_t)request[5]) << 16;
    bytes |= ((uint32_t)request[6]) << 8;
    bytes |= ((uint32_t)request[7]);
    wdt_reset();

    // Read specificed amount of data from memory starting at specified address
    for(int i = 0; i < bytes; i++){
        UART1_putchar(pgm_read_byte_far(start_addr+i));
    }
} // readback

/*
* Begin execution of installed firmware
* Print release message on serial
*/
void boot_firmware(void)
{
    // Start the Watchdog Timer.
    wdt_enable(WDTO_2S);

    // Release message begins at end of last firmware page
    uint16_t cur_address = eeprom_read_word(&fw_bytes);
    // Calculate end address of release message
    uint16_t message_end = cur_address + eeprom_read_word(&message_bytes);

    // Reset if firmware size is 0 (indicates no firmware is loaded).
    if(cur_address == 0){
        // Wait for watchdog timer to reset.
        while(1) __asm__ __volatile__("");
    }
    wdt_reset();

    // Write out release message to UART0.
    while(cur_address < message_end){
        uint8_t byte = pgm_read_byte_far(cur_address);
        UART0_putchar(byte);
        cur_address += 1;
    }
    // Send end byte to show end of message
    UART0_putchar(0x01);

    // Stop the Watchdog Timer.
    wdt_reset();
    wdt_disable();

    // Redirect program execution to address 0
    // to being firmware execution
    asm ("jmp 0000");
} // boot_firmware

/*
* Create a MAC from a key and input message
*/
void create_mac(unsigned char* out, unsigned char* in, uint16_t len, unsigned char type)
{
    // Create containers for hashing
    unsigned char key_in[MAX_AR_SIZE];
    unsigned char temp_hash[crypto_stream_xsalsa20_KEYBYTES+crypto_hash_sha512_BYTES];

    // Store key in appropriate arrays; choose readback or update key based on type parameter
    for(int i = 0; i < crypto_stream_xsalsa20_KEYBYTES; i++){
        key_in[i] = temp_hash[i] = (type == IS_UPDATE) ? update_key[i] : readback_key[i];
    }
    wdt_reset();

    // Transer input data to combined array of key and *in* message
    for(int i = 0; i < len; i++){
        key_in[crypto_stream_xsalsa20_KEYBYTES+i] = in[i];
    }
    wdt_reset();

    // Create two layer hash from key nonce and data, and key and layer 1
    // MAC has form: HASH[key : hash(key : in)]
    // Store final hash in *out* variable
    crypto_hash_sha512(temp_hash+crypto_stream_xsalsa20_KEYBYTES, key_in, crypto_stream_xsalsa20_KEYBYTES+len);
    crypto_hash_sha512(out, temp_hash, crypto_stream_xsalsa20_KEYBYTES+crypto_hash_sha512_BYTES);
}
