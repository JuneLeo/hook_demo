//
// Created by juneleo on 2024/1/13.
//

#include "person.h"
#include <android/log.h>

#include<stdio.h>
#include<unistd.h>
#include <jni.h>


void person::play() {
    __android_log_print(ANDROID_LOG_DEBUG,"elf-call","play");
    grow();
    pid_t id = fork();//创建子进程
    if(id == 0) {
        __android_log_print(ANDROID_LOG_DEBUG,"elf-call","play");
    } else {
        __android_log_print(ANDROID_LOG_DEBUG,"elf-call","play2");
    }

}

void person::grow() {
    __android_log_print(ANDROID_LOG_DEBUG,"elf-call","grow");
}