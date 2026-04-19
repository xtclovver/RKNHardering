#ifndef RKNHARDERING_NATIVE_SIGNS_PROBE_H
#define RKNHARDERING_NATIVE_SIGNS_PROBE_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved);

#ifdef __cplusplus
}
#endif

#endif
