#include <avr/pgmspace.h>

struct Frame {
    unsigned char data[SPM_PAGESIZE];
    uint16_t data_size;
    uint16_t version;
    uint8_t frame_no;
    uint8_t is_message;
};
