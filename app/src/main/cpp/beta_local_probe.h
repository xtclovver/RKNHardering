#ifndef RKNHARDERING_BETA_LOCAL_PROBE_H
#define RKNHARDERING_BETA_LOCAL_PROBE_H

#include <jni.h>

jobjectArray nativeBetaUnixDiagProbe(JNIEnv *env, jclass clazz, jobject cancellationSignal);
jobjectArray nativeBetaUnixPeerIdentityProbe(JNIEnv *env, jclass clazz, jint fd);
jobjectArray nativeBetaOriginalDestinationProbe(JNIEnv *env, jclass clazz, jint fd);
jobjectArray nativeBetaPktInfoProbe(JNIEnv *env, jclass clazz, jint fd);
jobjectArray nativeBetaTransitionMonitor(JNIEnv *env, jclass clazz, jint durationMs, jobject cancellationSignal);
jobjectArray nativeBetaExtendedRouteProbe(JNIEnv *env, jclass clazz, jint fd, jint uid, jobject cancellationSignal);

#endif
