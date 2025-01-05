package com.elf.call;

public class Hook {
    static {
        System.loadLibrary("hook");
    }
    public static native void init();
}
