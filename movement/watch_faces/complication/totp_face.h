#ifndef TOTP_FACE_H_
#define TOTP_FACE_H_

#include "movement.h"

static const uint8_t num_keys = 3;
static uint8_t keys[] = {
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef, // 1 - JBSWY3DPEHPK3PXP
    0x5c, 0x0d, 0x27, 0x6b, 0x6d, 0x9a, 0x01, 0x22, 0x20, 0x4f, // 2 - E9M348K0ADIDFBC2
    0x77, 0x2e, 0x48, 0xc3, 0x91, 0xaa, 0x34, 0xac, 0x3d, 0xba, // 3 - O4XERQ4RVI2KYPN274NHZOJKK6CUCHPM5QEUDRS3TOVMMDDR4ZQ4IZPJNJNDU2VCISO25HLHFENH4D3VJW6V5C7EMSXUXJYMRX6D6EA
    0xff, 0x1a, 0x7c, 0xb9, 0x2a, 0x57, 0x85, 0x41, 0x1d, 0xec,
    0xec, 0x09, 0x41, 0xc6, 0x5b, 0x9b, 0xaa, 0xc6, 0x0c, 0x71,
    0xe6, 0x61, 0xc4, 0x65, 0xe9, 0x6a, 0x5a, 0x3a, 0x6a, 0xa2,
    0x44, 0x9d, 0xae, 0x9d, 0x67, 0x29, 0x1a, 0x7e, 0x0f, 0x75,
    0x4d, 0xbd, 0x5e, 0x8b, 0xe4, 0x64, 0xaf, 0x4b, 0xa7, 0x0c,
    0x8d, 0xfc, 0x3f, 0x10
};
static const uint8_t key_sizes[] = {
    10,
    10,
    64
};
static const uint32_t timesteps[] = {
    30,
    30,
    0
};
static const char labels[][2] = {
    { 'a', 'b' },
    { 'c', 'd' },
    { 'e', 'f' }
};

typedef struct {
    uint32_t timestamp;
    uint8_t steps;
    uint32_t current_code;
    uint8_t current_index;
    uint8_t current_key_offset;
    uint32_t hotp_counter[num_keys];
} totp_state_t;

void totp_face_setup(movement_settings_t *settings, uint8_t watch_face_index, void ** context_ptr);
void totp_face_activate(movement_settings_t *settings, void *context);
bool totp_face_loop(movement_event_t event, movement_settings_t *settings, void *context);
void totp_face_resign(movement_settings_t *settings, void *context);

#define totp_face ((const watch_face_t){ \
    totp_face_setup, \
    totp_face_activate, \
    totp_face_loop, \
    totp_face_resign, \
    NULL, \
})

#endif // TOTP_FACE_H_
