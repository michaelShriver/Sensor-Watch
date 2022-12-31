#include <stdlib.h>
#include <string.h>
#include "totp_face.h"
#include "watch.h"
#include "watch_utility.h"
#include "TOTP.h"

// Use https://cryptii.com/pipes/base32-to-hex to convert base32 to hex
// Use https://totp.danhersam.com/ to generate test codes for verification

// HOTP keys are specified by setting a timestep value of '0' for the key
// Long press the light button to increment the code for HOTP

void totp_face_setup(movement_settings_t *settings, uint8_t watch_face_index, void ** context_ptr) {
    (void) settings;
    (void) watch_face_index;
    if(*context_ptr == NULL){
        *context_ptr = malloc(sizeof(totp_state_t));
        memset(*context_ptr, 0, sizeof(totp_state_t));
    }
    totp_state_t *totp_state = (totp_state_t *)*context_ptr;
    // Initialize the counter with initial values (optional)
    for(uint8_t i = 0;i < NUM_KEYS; i++){
        totp_state->hotp_counter[i] = counterinit[i];
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
                sprintf(buf, "%c%c%2d%06lu", labels[index][0], labels[index][1], valid_for, totp_state->current_code);
            } else {
                TOTP(keys + totp_state->current_key_offset, key_sizes[index], timesteps[index]);
                totp_state->current_code = getCodeFromSteps(totp_state->hotp_counter[index]);
                valid_for = totp_state->hotp_counter[index];
                sprintf(buf, "%c%c  %06lu", labels[index][0], labels[index][1], totp_state->current_code);
            }

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
                sprintf(buf, "%c%c  %06lu", labels[index][0], labels[index][1], totp_state->current_code);

                watch_display_string(buf, 0);
            }
            break;
        case EVENT_TIMEOUT:
            movement_move_to_face(0);
            break;
        case EVENT_ALARM_BUTTON_UP:
            if (index + 1 < NUM_KEYS) {
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
                sprintf(buf, "%c%c  %06lu", labels[totp_state->current_index][0], labels[totp_state->current_index][1], totp_state->current_code);

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
