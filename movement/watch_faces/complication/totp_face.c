#include <stdlib.h>
#include <string.h>
#include "totp_face.h"
#include "watch.h"
#include "watch_utility.h"
#include "TOTP.h"

// Use https://cryptii.com/pipes/base32-to-hex to convert base32 to hex
// Use https://totp.danhersam.com/ to generate test codes for verification

// HOTP keys are specified by setting a timestep value of '0' for the key

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

void totp_face_setup(movement_settings_t *settings, uint8_t watch_face_index, void ** context_ptr) {
    (void) settings;
    (void) watch_face_index;
    if(*context_ptr == NULL){
        *context_ptr = malloc(sizeof(totp_state_t));
        memset(*context_ptr, 0, sizeof(totp_state_t));
    }
}

void totp_face_activate(movement_settings_t *settings, void *context) {
    (void) settings;
    totp_state_t *totp_state = (totp_state_t *)context;
    uint8_t index = totp_state->current_index;
    TOTP(keys, key_sizes[index], timesteps[index]);
    totp_state->timestamp = watch_utility_date_time_to_unix_time(watch_rtc_get_date_time(), movement_timezone_offsets[settings->bit.time_zone] * 60);
    // Check for initial key type and set initial code
    if (timesteps[index] != 0) {
        totp_state->current_code = getCodeFromTimestamp(totp_state->timestamp);
    } else {
        totp_state->current_code = getCodeFromSteps(totp_state->hotp_counter[index]);
    }
}

bool totp_face_loop(movement_event_t event, movement_settings_t *settings, void *context) {
    (void) settings;

    totp_state_t *totp_state = (totp_state_t *)context;
    char buf[14];
    uint8_t valid_for;
    div_t result;
    uint8_t index = totp_state->current_index;

    switch (event.event_type) {
        case EVENT_TICK:
            totp_state->timestamp++;
            if (timesteps[index] != 0) {
                result = div(totp_state->timestamp, timesteps[index]);
                if (result.quot != totp_state->steps) {
                    totp_state->current_code = getCodeFromTimestamp(totp_state->timestamp);
                    totp_state->steps = result.quot;
                }
                valid_for = timesteps[index] - result.rem;
                sprintf(buf, "%c%c%2d%06lu", labels[index][0], labels[index][1], valid_for, totp_state->current_code);

                watch_display_string(buf, 0);
            }
            break;
        case EVENT_ACTIVATE:
            if (timesteps[index] != 0) {
                result = div(totp_state->timestamp, timesteps[index]);
                if (result.quot != totp_state->steps) {
                    totp_state->current_code = getCodeFromTimestamp(totp_state->timestamp);
                    totp_state->steps = result.quot;
                }
                valid_for = timesteps[index] - result.rem;
            } else {
                TOTP(keys + totp_state->current_key_offset, key_sizes[index], timesteps[index]);
                totp_state->current_code = getCodeFromSteps(totp_state->hotp_counter[index]);
                valid_for = totp_state->hotp_counter[index];
            }
            sprintf(buf, "%c%c%2d%06lu", labels[index][0], labels[index][1], valid_for, totp_state->current_code);

            watch_display_string(buf, 0);
            break;
        case EVENT_MODE_BUTTON_UP:
            movement_move_to_next_face();
            break;
        case EVENT_LIGHT_BUTTON_DOWN:
            movement_illuminate_led();
            break;
        case EVENT_LIGHT_LONG_PRESS:
            // If key is HOTP, increment counter
            if (timesteps[index] == 0) {
                totp_state->hotp_counter[index]++;
                totp_state->current_code = getCodeFromSteps(totp_state->hotp_counter[index]);
                valid_for = totp_state->hotp_counter[index];
                sprintf(buf, "%c%c%2d%06lu", labels[index][0], labels[index][1], valid_for, totp_state->current_code);

                watch_display_string(buf, 0);
            }
            break;
        case EVENT_TIMEOUT:
            movement_move_to_face(0);
            break;
        case EVENT_ALARM_BUTTON_UP:
            if (index + 1 < num_keys) {
                totp_state->current_key_offset += key_sizes[index];
                totp_state->current_index++;
            } else {
                // wrap around to first key
                totp_state->current_key_offset = 0;
                totp_state->current_index = 0;
            }
            if (timesteps[totp_state->current_index] != 0) {
                TOTP(keys + totp_state->current_key_offset, key_sizes[totp_state->current_index], timesteps[totp_state->current_index]);
            } else {
                TOTP(keys + totp_state->current_key_offset, key_sizes[totp_state->current_index], totp_state->hotp_counter[totp_state->current_index]);
                totp_state->current_code = getCodeFromSteps(totp_state->hotp_counter[totp_state->current_index]);
                valid_for = totp_state->hotp_counter[totp_state->current_index];
                sprintf(buf, "%c%c%2d%06lu", labels[totp_state->current_index][0], labels[totp_state->current_index][1], valid_for, totp_state->current_code);

                watch_display_string(buf, 0);
            }
            break;
        case EVENT_ALARM_BUTTON_DOWN:
        case EVENT_ALARM_LONG_PRESS:
        default:
            break;
    }

    return true;
}

void totp_face_resign(movement_settings_t *settings, void *context) {
    (void) settings;
    (void) context;
}
