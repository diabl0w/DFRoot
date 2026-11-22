#ifndef EXP98260_H
#define EXP98260_H
#include <stdint.h>
#include <stddef.h>

/* Set these to the target build. Empty string = accept any kernel. */
#define DF2_TARGET_KERNEL "6.18.21-android17-5-pc5d9a20-abogkiA066BXXU8DZJ7-4k"

int escalate_98260(const char *ko_path);
#endif
