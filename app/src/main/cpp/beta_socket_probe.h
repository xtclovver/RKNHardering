#ifndef RKNHARDERING_BETA_SOCKET_PROBE_H
#define RKNHARDERING_BETA_SOCKET_PROBE_H

#include <jni.h>

jobjectArray nativeBetaSocketIdentity(JNIEnv *env, jclass clazz, jint fd);
jobjectArray nativeBetaInetDiagByCookie(JNIEnv *env, jclass clazz, jint fd, jobject cancellationSignal);
jobjectArray nativeBetaNetdIdentity(JNIEnv *env, jclass clazz, jint fd);

#endif
