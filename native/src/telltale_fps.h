#pragma once
#include <cstddef>
#include <cstdint>
#include <jni.h>

class DynarmicHost;
struct TelltaleFpsBinding { uint32_t node = 0, callback = 0; };
bool VerifyTelltaleFpsImage(JNIEnv* env, const uint8_t* image, size_t size);
uint32_t RegisterTelltaleFpsSetter(DynarmicHost& host);
TelltaleFpsBinding PrepareTelltaleFpsBinding(DynarmicHost& host);
bool InstallTelltaleFpsBinding(DynarmicHost& host, TelltaleFpsBinding binding);
jint InitTelltaleFpsUi(JNIEnv* env, jclass cls);
void RefreshTelltaleFpsDisplay(JNIEnv* env, jclass cls, jfloat actual_hz);

// Share the existing UI looper/eventfd for sparse SDL Window lifecycle handoff.
void NotifyTelltaleUiLifecycle();
bool TelltaleUiLifecycleOwner();
void ApplyPendingSdlWindowLifecycle(JNIEnv* env);
