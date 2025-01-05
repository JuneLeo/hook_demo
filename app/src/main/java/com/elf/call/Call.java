package com.elf.call;

public class Call {

    public static  String LIB_CALL = "libcall.so";

    public static native String printNativeMethodAddress();

    public static native String callByAddress(long address);

    public static native String dobbyHookTest();

    public static native String doNativeName();
}
