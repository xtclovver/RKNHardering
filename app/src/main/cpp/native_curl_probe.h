#ifndef RKNHARDERING_NATIVE_CURL_PROBE_H
#define RKNHARDERING_NATIVE_CURL_PROBE_H

#include <jni.h>

jobjectArray ExecuteNativeCurlRequest(
    JNIEnv* env,
    jstring url,
    jstring interface_name,
    jstring method,
    jobjectArray headers,
    jstring body,
    jboolean follow_redirects,
    jstring proxy_url,
    jint proxy_type,
    jobjectArray resolve_rules,
    jint ip_resolve_mode,
    jint timeout_ms,
    jint connect_timeout_ms,
    jstring ca_bundle_path,
    jboolean debug_verbose,
    jstring request_id
);

jboolean CancelNativeCurlRequest(
    JNIEnv* env,
    jstring request_id
);

#endif
