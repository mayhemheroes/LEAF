#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../leaf/leaf.h"

#define TOTAL_OPTIONS 6
#define MEMPOOL_SIZE 1024 * 24
#define SET_VAR(var,input,t,size) memcpy(&var,input,sizeof(t)); size -= sizeof(t); input += sizeof(t);

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
    if (Size > 1) {
        uint8_t* inputData = (uint8_t*) malloc(Size);
        const uint8_t* inputDataStart = inputData;
        memcpy(inputData, Data, Size);

        uint8_t option; 
        SET_VAR(option, inputData, uint8_t, Size);

        switch (option % TOTAL_OPTIONS) {
            case 0:
                if (Size >= 8) {
                    tPRCReverb reverb;
                    float t60;
                    float mix;

                    SET_VAR(t60, inputData, float, Size);
                    SET_VAR(mix, inputData, float, Size);

                    tPRCReverb_init(&reverb, t60, &leaf);
                    tPRCReverb_setMix(&reverb, mix);

                    float val;
                    while(Size >= 4) {
                        SET_VAR(val, inputData, float, Size);
                        tPRCReverb_tick(&reverb, val);
                    }

                    tPRCReverb_free(&reverb);
                }
                break;
            case 1:
                if (Size >= 4) {
                    tSampleReducer sepRed;
                    float ratio;

                    SET_VAR(ratio, inputData, float, Size);

                    tSampleReducer_init(&sepRed, &leaf);
                    tSampleReducer_setRatio(&sepRed, ratio);

                    float val;
                    while(Size >= 4) {
                        SET_VAR(val, inputData, float, Size);
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
                    while(Size >= 4) {
                        SET_VAR(val, inputData, float, Size);
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
                    while(Size >= 8) {
                        SET_VAR(val1, inputData, float, Size);
                        SET_VAR(val2, inputData, float, Size);
                        tTalkbox_tick(&box, val1, val2);
                    }

                    tTalkbox_free(&box);
                }
                break;
            case 4:
                {
                    tTwoZero tz;

                    tTwoZero_init(&tz, &leaf);

                    float val;
                    while(Size >= 4) {
                        SET_VAR(val, inputData, float, Size);
                        tTwoZero_tick(&tz, val);
                    }

                    tTwoZero_free(&tz);
                }
                break;
            case 5:
                {
                    tPoly poly;

                    tPoly_init(&poly, 255, &leaf);

                    int intVal;
                    uint8_t u8Val;
                    float floatVal;
                    uint8_t opt;

                    while(Size > 1) {
                        SET_VAR(opt, inputData, uint8_t, Size);
                        switch (opt) {
                            case 0:
                                if (Size >= 5) {
                                    SET_VAR(intVal, inputData, int, Size);
                                    SET_VAR(u8Val, inputData, uint8_t, Size);
                                    tPoly_noteOn(&poly, intVal, u8Val);
                                }
                                break;
                            case 1:
                                if (Size >= 1) {
                                    SET_VAR(u8Val, inputData, uint8_t, Size);
                                    tPoly_noteOff(&poly, u8Val);
                                }
                                break;
                            case 2:
                                if (Size >= 4) {
                                    SET_VAR(floatVal, inputData, float, Size);
                                    tPoly_setPitchBend(&poly, floatVal);
                                }
                                break;
                        }
                        tPoly_tickPitch(&poly);
                        tPoly_tickPitchBend(&poly);
                        tPoly_tickPitchGlide(&poly);
                    }

                    tPoly_free(&poly);
                }
                break;
        }

        free(inputDataStart);
    }

    return 0;
}