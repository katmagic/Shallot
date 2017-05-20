#ifndef GLOBALS_H
#define GLOBALS_H

#include "config.h"

#include <regex.h>
#include <stdint.h>
#include <pthread.h>

// global variables (saves us the trouble of passing pointers around)
// TODO: stop being lazy and pass this stuff where it's needed
// TODO: also put settings in a struct
uint64_t loop, elim;
uint8_t found, monitor, maxexectime;
uint8_t continuous;
pthread_t lucky_thread;
regex_t *regex;

#endif
