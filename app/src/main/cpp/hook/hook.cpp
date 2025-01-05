//
// Created by juneleo on 2025/1/2.
//
#include <jni.h>
#include "elf_parse.h"
#include "log.h"
#include <pthread.h>
#include <malloc.h>
#include <vector>


int (*origin_pthread_create_hook)(pthread_t *thread, const pthread_attr_t *attr,
                                  void *(*start_routine)(void *), void *arg);


int hook_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                        void *(*start_routine)(void *), void *arg) {
    XH_LOG_DEBUG("hook_pthread_create start origin address=%p", origin_pthread_create_hook);

    // hook before
    int result = origin_pthread_create_hook(thread, attr, start_routine, arg);


    // hook after
    XH_LOG_DEBUG("hook_pthread_create thread id = %d", pthread_gettid_np(*thread));
    char name[16];
    if (pthread_getname_np(*thread, name, 16) == 0) {
        XH_LOG_DEBUG("hook_pthread_create thread_name = %s", name);
    }


    return result;
}

void (*a)();

void b() {
    XH_LOG_DEBUG("b do");
}

void *(*origin_malloc)(size_t size);

void *hook_malloc(size_t size) {
    XH_LOG_DEBUG("malloc call");
//    return origin_malloc(size);
}


static bool isHook = false;

extern "C"
JNIEXPORT void JNICALL
Java_com_elf_call_Hook_init(JNIEnv *env, jclass thiz) {
    if(!isHook) {
        std::vector<ShareLibrary> vector;
        xh_maps(&vector);
        for (const auto &item: vector) {
            std::string pathname = item.pathname;
            XH_LOG_DEBUG("ShareLibrary pathname = %s, address=0x%lx", pathname.c_str(), item.base_addr);
            xh_elf_t xhElf{};
            xh_elf_init(&xhElf, item.base_addr, pathname.c_str());
            xh_elf_hook(&xhElf, "pthread_create", (void *) hook_pthread_create, (void **) &origin_pthread_create_hook);
//        xh_elf_hook(&xhElf, "malloc", (void *) hook_malloc, (void **) &origin_malloc);
        }
        isHook = true;
    }
}