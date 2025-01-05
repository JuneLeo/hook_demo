#include <jni.h>
#include <string>
#include <android/log.h>
#include "dobby.h"
#include <pthread.h>
#include <elf.h>
#include <link.h>
#include <android/data_space.h>

static char *(*origin_test)();

char *test() {
    return "test";
}


char *hook_test() {
    return "hook_test"; // bhook
}

int (*origin_pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
                              void *(*start_routine)(void *), void *arg);


int hook_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                        void *(*start_routine)(void *), void *arg) {

    // hook before
    int result = origin_pthread_create(thread, attr, start_routine, arg);

    // hook after
    __android_log_print(ANDROID_LOG_DEBUG, "song", "hook_pthread_create thread id = %d", pthread_gettid_np(*thread));
    char name[16];
    if (pthread_getname_np(*thread, name, 16) == 0) {
        __android_log_print(ANDROID_LOG_DEBUG, "song", "hook_pthread_create thread_name = %s", name);
    }


    return result;
}


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint r = vm->GetEnv((void **) &env, JNI_VERSION_1_4);

    if (r != JNI_OK) {
        return r;
    }

//    DobbyHook((void *) test, (void *) hook_test, (void **) &origin_test);
//    DobbyHook(DobbySymbolResolver(NULL, "pthread_create"), (void *)hook_pthread_create, (void **) &origin_pthread_create);

    return JNI_VERSION_1_4;
}

extern "C"
JNIEXPORT void JNICALL Java_com_elf_call_MainActivity_nativeMethod() {
    __android_log_print(ANDROID_LOG_DEBUG, "song", "nativeMethod");
}

void * thr_fn(void *arg)
{
    __android_log_print(ANDROID_LOG_DEBUG, "song", "thr_fn do");
    return NULL;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_elf_call_Call_printNativeMethodAddress(JNIEnv *env, jclass clazz) {
    std::string hello = "Hello from C++";
    __android_log_print(ANDROID_LOG_DEBUG, "song", "address=%p", &Java_com_elf_call_MainActivity_nativeMethod);
    return env->NewStringUTF(hello.c_str());
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_elf_call_Call_callByAddress(JNIEnv *env, jclass clazz, jlong address) {
    __android_log_print(ANDROID_LOG_DEBUG, "song", "callByAddress - address=%ld", address);
    void (*funcPtr)() = reinterpret_cast<void (*)(void)>(address);
    funcPtr();
    __android_log_print(ANDROID_LOG_DEBUG, "song", "callByAddress - address success");
    return env->NewStringUTF("success");
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_elf_call_Call_dobbyHookTest(JNIEnv *env, jclass clazz) {
//    __android_log_print(ANDROID_LOG_DEBUG, "song", "origin - %s", origin_test());
//    char *t = test();
//    __android_log_print(ANDROID_LOG_DEBUG, "song", "hook - %s", t);

//    pthread_t pthread;
//    pthread_create(&pthread, NULL, thr_fn, NULL);

    return env->NewStringUTF("song");
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_elf_call_Call_doNativeName(JNIEnv *env, jclass clazz) {
    pthread_t pthread;
    pthread_create(&pthread, NULL, thr_fn, NULL);

//    malloc(sizeof(int));

    return env->NewStringUTF("song");
}