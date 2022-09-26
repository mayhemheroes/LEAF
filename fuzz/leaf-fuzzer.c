#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../leaf/leaf.h"

#define TOTAL_OPTIONS 5
#define MEMPOOL_SIZE 1024 * 8
#define SET_VAR(var,input,t,size) memcpy(&var,input,sizeof(t)); size -= sizeof(t);

LEAF leaf;
char* mempool;

float exampleRandom()
{
    return ((float)rand()/(float)(RAND_MAX));
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    mempool = (char*) malloc(MEMPOOL_SIZE);
    LEAF_init(&leaf, 44100, mempool, MEMPOOL_SIZE, &exampleRandom);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size > 2) {
        uint8_t option = Data[0];
        Size--;

        switch (Data[0] % TOTAL_OPTIONS) {
            case 0:
                if (Size > 4) {
                    tPRCReverb reverb;
                    float t60;
                    SET_VAR(t60, (Data + 1), float, Size);
                    tPRCReverb_init(&reverb, t60, &leaf);
                    float val;
                    for (int i = 0; Size > 4; i += 4) {
                        SET_VAR(val, Data + 5 + i, float, Size);
                        tPRCReverb_tick(&reverb, val);
                    }
                    tPRCReverb_free(&reverb);
                }
                break;
            case 1:
                if (Size > 4) {
                    tSampleReducer sepRed;
                    float ratio;
                    SET_VAR(ratio, (Data + 1), float, Size);
                    tSampleReducer_init(&sepRed, &leaf);
                    tSampleReducer_setRatio(&sepRed, ratio);
                    float val;
                    for (int i = 0; Size > 4; i += 4) {
                        SET_VAR(val, Data + 5 + i, float, Size);
                        tSampleReducer_tick(&sepRed, val);
                    }
                    tSampleReducer_free(&sepRed);
                }
                break;
            case 2:
                {
                    tLockhartWavefolder semp;
                    tLockhartWavefolder_init(&semp, &leaf);
                    float val;
                    for (int i = 0; Size > 4; i += 4) {
                        SET_VAR(val, Data + 1 + i, float, Size);
                        tLockhartWavefolder_tick(&semp, val);
                    }
                    tLockhartWavefolder_free(&semp);
                }
                break;
            case 3:
                {
                    tTalkbox box;
                    tTalkbox_init(&box, 128, &leaf);
                    float val1;
                    float val2;
                    for (int i = 0; Size > 8; i += 8) {
                        SET_VAR(val1, Data + 1 + i, float, Size);
                        SET_VAR(val2, Data + 1 + i + 1, float, Size);
                        tTalkbox_tick(&box, val1, val2);
                    }
                    tTalkbox_free(&box);
                }
                break;
            // case 4:
            //     if (Size > 12) {
            //         float low;
            //         float high;
            //         float hystersis;
            //         SET_VAR(low, Data + 1, float, Size);
            //         SET_VAR(high, Data + 5, float, Size);
            //         SET_VAR(hystersis, Data + 9, float, Size);

            //         tPeriodDetector dec;
            //         tPeriodDetector_init(&dec, low, high, hystersis, &leaf);

            //         float val;
            //         for (int i = 0; Size > 4; i += 4) {
            //             SET_VAR(val, Data + 13 + i, float, Size);
            //             tPeriodDetector_tick(&dec, val);
            //         }

            //         tPeriodDetector_free(&dec);
            //     }
            //     break;
            case 4:
                {
                    tTwoZero tz;
                    tTwoZero_init(&tz, &leaf);
                    float val;
                    for (int i = 0; Size > 4; i += 4) {
                        SET_VAR(val, Data + 1 + i, float, Size);
                        tTwoZero_tick(&tz, val);
                    }
                    tTwoZero_free(&tz);
                }
                break;
        }
    }

    return 0;
}