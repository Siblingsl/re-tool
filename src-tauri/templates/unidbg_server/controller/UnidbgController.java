package com.retool.unidbg_server.controller;

import com.retool.unidbg_server.service.UnidbgService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/unidbg")
public class UnidbgController {

    @Autowired
    private UnidbgService service;

    @PostMapping("/{method}")
    public String handle(@PathVariable String method, @RequestBody Map<String, Object> payload) {
        // 1. 获取参数
        String data = payload.getOrDefault("data", "").toString();

        // 2. 捕获执行过程中的所有异常
        try {
            System.out.println(">>> 收到请求: " + method + ", 参数: " + data);

            // 目前只处理 do_work，你可以根据 {method} 扩展 switch case
            return service.doWork(data);

        } catch (Throwable e) {
            // 🔥 关键：打印堆栈到控制台，方便调试
            e.printStackTrace();

            // 🔥 关键：将错误信息返回给前端，而不是报 500
            // 如果是 Unidbg 报错，这里通常能看到具体原因，比如 "Signature not found"
            return "执行出错: " + e.toString() + "\n\n详细堆栈请查看终端控制台。";
        }
    }
}