# hook_demo
* plt hook 代码来自xhook的核心代码
* inline hook 使用的Dobby库


## plt hook
```c++
extern "C"
JNIEXPORT void JNICALL
Java_com_elf_call_Hook_init(JNIEnv *env, jclass thiz) {
    if(!isHook) {
        std::vector<ShareLibrary> vector;
        xh_maps(&vector);  // 解析maps文件，获取程序的基地址
        for (const auto &item: vector) {
            std::string pathname = item.pathname;
            XH_LOG_DEBUG("ShareLibrary pathname = %s, address=0x%lx", pathname.c_str(), item.base_addr);
            xh_elf_t xhElf{};
            xh_elf_init(&xhElf, item.base_addr, pathname.c_str()); // 解析elf文件
            xh_elf_hook(&xhElf, "pthread_create", (void *) hook_pthread_create, (void **) &origin_pthread_create_hook); // hook代码
//        xh_elf_hook(&xhElf, "malloc", (void *) hook_malloc, (void **) &origin_malloc);
        }
        isHook = true;
    }
}
```

## inline hook

```c++
    DobbyHook((void *) test, (void *) hook_test, (void **) &origin_test);
    DobbyHook(DobbySymbolResolver(NULL, "pthread_create"), (void *)hook_pthread_create, (void **) &origin_pthread_create);
```