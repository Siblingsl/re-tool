package com.retool.unidbg_server.core;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import org.springframework.core.io.ClassPathResource;
import org.apache.commons.io.FileUtils;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.File;
import java.io.IOException;

public abstract class AbstractUnidbgWorker extends AbstractJni {
    protected AndroidEmulator emulator;
    protected VM vm;
    protected DvmClass module;

    public abstract String getSoFileName();

    public abstract String getTargetClass();

    public abstract boolean is64Bit();

    protected void onLoaded(AndroidEmulator emulator, VM vm, DvmClass module) {
    }

    @PostConstruct
    public void init() throws IOException {
        boolean is64 = is64Bit();
        String soName = getSoFileName();
        System.out.println(">>> 初始化: " + soName + " [" + (is64 ? "64-bit" : "32-bit") + "]");

        emulator = (is64 ? AndroidEmulatorBuilder.for64Bit() : AndroidEmulatorBuilder.for32Bit())
                .setProcessName("com.retool.worker").build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));

        // 1. 寻找文件
        File soFile = new File("src/main/resources/natives/" + soName);
        if (!soFile.exists()) {
            File tmpFile = new File(System.getProperty("java.io.tmpdir"), soName);
            ClassPathResource res = new ClassPathResource("natives/" + soName);
            if (res.exists()) {
                FileUtils.copyInputStreamToFile(res.getInputStream(), tmpFile);
                soFile = tmpFile;
            }
        }

        // 2. 创建空 VM
        vm = emulator.createDalvikVM((File) null);
        vm.setJni(this);
        vm.setVerbose(true);

        // 加载依赖库 libc++_shared.so
        File libCpp = new File("src/main/resources/natives/libc++_shared.so");
        if (libCpp.exists()) {
            System.out.println(">>> 优先加载: libc++_shared.so");
            byte[] cppData = FileUtils.readFileToByteArray(libCpp);
            vm.loadLibrary("c++_shared", cppData, true);
        }

        // 3. 先加载类 (修复顺序)
        if (getTargetClass() != null && !getTargetClass().isEmpty()) {
            System.out.println(">>> 预加载类: " + getTargetClass());
            module = vm.resolveClass(getTargetClass());
        }

        // 4. 再加载 SO (修复 ZipException)
        System.out.println(">>> 加载目标 SO...");
        byte[] soData = FileUtils.readFileToByteArray(soFile);
        String libName = soName.replace("lib", "").replace(".so", "");
        
        DalvikModule dm = vm.loadLibrary(libName, soData, true);
        dm.callJNI_OnLoad(emulator);

        System.out.println("✅ 初始化完成");
        onLoaded(emulator, vm, module);
    }

    @PreDestroy
    public void destroy() {
        try {
            if (emulator != null)
                emulator.close();
        } catch (IOException e) {
        }
    }
}