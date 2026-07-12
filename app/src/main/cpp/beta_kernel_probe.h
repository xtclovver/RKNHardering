#ifndef RKNHARDERING_BETA_KERNEL_PROBE_H
#define RKNHARDERING_BETA_KERNEL_PROBE_H

#include <jni.h>

jobjectArray nativeBetaWireGuardProbe(JNIEnv *env, jclass clazz, jobject cancellationSignal);
jobjectArray nativeBetaOvpnProbe(JNIEnv *env, jclass clazz, jobject cancellationSignal);
jobjectArray nativeBetaXfrmProbe(JNIEnv *env, jclass clazz, jboolean imsContext, jobject cancellationSignal);
jobjectArray nativeBetaTunFdProbe(JNIEnv *env, jclass clazz, jobject cancellationSignal);
jobjectArray nativeBetaBpfNetfilterProbe(JNIEnv *env, jclass clazz, jboolean aggressive, jobject cancellationSignal);

#endif
