#include "reporter.h"

#include <stdarg.h>
#include <stdio.h>

static jmethodID report_mid;

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved __attribute__((unused))) {
    JNIEnv *env;
    (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4);
    jclass clz = (*env)->FindClass(env, "df/root/IReporter");
    report_mid = (*env)->GetMethodID(env, clz, "report", "(Ljava/lang/String;)V");
    return JNI_VERSION_1_4;
}

void reportfmt(struct Reporter *reporter, const char *format, ...) {
    if (!reporter) return;
    va_list arguments;
    va_start(arguments, format);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    jstring message = (*reporter->env)->NewStringUTF(reporter->env, buffer);
    (*reporter->env)->CallVoidMethod(reporter->env, reporter->obj, report_mid, message);
    (*reporter->env)->ExceptionClear(reporter->env);
    (*reporter->env)->DeleteLocalRef(reporter->env, message);
}
