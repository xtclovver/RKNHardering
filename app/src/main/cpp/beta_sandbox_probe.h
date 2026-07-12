#pragma once

#include <jni.h>

jobjectArray nativeBetaSandboxSnapshot(JNIEnv *env, jclass clazz, jobjectArray paths, jboolean aggressive);
