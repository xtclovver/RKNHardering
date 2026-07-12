#ifndef RKNHARDERING_BETA_NETLINK_PROBE_H
#define RKNHARDERING_BETA_NETLINK_PROBE_H

#include <jni.h>

jobjectArray nativeBetaRoutingSnapshot(JNIEnv *env, jclass clazz, jint fd, jint uid, jobject cancellationSignal);

#endif
