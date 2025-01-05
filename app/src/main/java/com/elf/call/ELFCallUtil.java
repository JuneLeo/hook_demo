package com.elf.call;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ELFCallUtil {

    public static String getCopyLibsPath(Context context, String libName) {
        String libDir = String.format("/data/data/%s/files/libs", context.getPackageName());
        return libDir + "/" + libName;
    }

    public static void extractSoFromApk(Context context, String libName) {
        String apkPath = context.getPackageCodePath(); // 获取 APK 路径

        try (ZipFile zipFile = new ZipFile(apkPath)) {
            ZipEntry entry = zipFile.getEntry("lib/arm64-v8a/" + libName);
            File outputFile = new File(getCopyLibsPath(context, libName));
            if (outputFile.exists()) {
                outputFile.delete();
            }
            outputFile.getParentFile().mkdirs();

            if (!outputFile.exists()) {
                try (InputStream is = zipFile.getInputStream(entry);
                     FileOutputStream fos = new FileOutputStream(outputFile)) {

                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = is.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                    }
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * 7866a73000-7866ab6000 r-xp 00000000 fe:2a 707081                         /data/data/com.elf.call/app_libs/arm64-v8a/libcall.so
     * 7866ab6000-7866abb000 r--p 00042000 fe:2a 707081                         /data/data/com.elf.call/app_libs/arm64-v8a/libcall.so
     * 7866abb000-7866abc000 rw-p 00046000 fe:2a 707081                         /data/data/com.elf.call/app_libs/arm64-v8a/libcall.so
     * <p>
     * <p>
     *
     * @param
     */
    public static long getBaseAddress(Context context, String libName) {
        File file = new File("/proc/self/maps");
        FileReader fileReader = null;
        try {
            fileReader = new FileReader(file);
            BufferedReader reader = new BufferedReader(fileReader);
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("r-xp") && line.contains(ELFCallUtil.getCopyLibsPath(context, libName))) {
                    int i = line.indexOf("-");
                    if (i != -1) {
                        String substring = line.substring(0, i);
                        long aLong = Long.parseLong(substring, 16);
                        return aLong;
                    }
                }
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (fileReader != null) {
                try {
                    fileReader.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return 0;
    }
}