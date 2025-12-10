package com.retool.unidbg_server.service;

import com.retool.unidbg_server.core.AbstractUnidbgWorker;
import com.github.unidbg.linux.android.dvm.*;
import org.springframework.stereotype.Service;

@Service
public class UnidbgService extends AbstractUnidbgWorker {

    // === 1. 配置区 ===
    @Override
    public boolean is64Bit() {
        return false;
    } // true=64位, false=32位

    @Override
    public String getSoFileName() {
        return "libttEncrypt.so";
    }

    @Override
    public String getTargetClass() {
        return "com/example/MainActivity";
    }

    // === 2. 调用入口 ===
    public String doWork(String args) {
        System.out.println("调用参数: " + args);
        return "Unidbg 运行成功: " + args;
    }

    // === 3. 补环境 ===
    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }
}