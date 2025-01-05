//
// Created by juneleo on 2025/1/2.
//

#ifndef ELF_CALL_LOG_H
#define ELF_CALL_LOG_H
#include <android/log.h>


#define XH_LOG_TAG "hook"
#define XH_LOG_DEBUG(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, XH_LOG_TAG, fmt, ##__VA_ARGS__);
#define XH_LOG_INFO(fmt, ...)  __android_log_print(ANDROID_LOG_INFO,  XH_LOG_TAG, fmt, ##__VA_ARGS__);
#define XH_LOG_WARN(fmt, ...)  __android_log_print(ANDROID_LOG_WARN,  XH_LOG_TAG, fmt, ##__VA_ARGS__);
#define XH_LOG_ERROR(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, XH_LOG_TAG, fmt, ##__VA_ARGS__);


#endif //ELF_CALL_LOG_H
