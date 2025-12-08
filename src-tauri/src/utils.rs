use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

// 必须公开 pub
pub fn cmd_exec(cmd: &str, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new(cmd);
    command.args(args);
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000); 
    
    let output = command.output().map_err(|e| e.to_string())?;
    
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if stderr.is_empty() {
        Ok(stdout)
    } else {
        Ok(format!("{}\n[Stderr]: {}", stdout, stderr))
    }
}

pub fn get_android_label(pkg: &str) -> String {
    match pkg {
        "com.tencent.mm" => "微信".to_string(),
        "com.ss.android.ugc.aweme" => "抖音".to_string(),
        "com.eg.android.AlipayGphone" => "支付宝".to_string(),
        "tv.danmaku.bili" => "哔哩哔哩".to_string(),
        "com.sina.weibo" => "微博".to_string(),
        "com.xingin.xhs" => "小红书".to_string(),
        "com.jingdong.app.mall" => "京东".to_string(),
        "com.taobao.taobao" => "淘宝".to_string(),
        "com.coolapk.market" => "酷安".to_string(),
        "bin.mt.plus" => "MT管理器".to_string(),
        "com.netease.cloudmusic" => "网易云音乐".to_string(),
        _ => {
            let last_part = pkg.split('.').last().unwrap_or(pkg);
            let name = last_part.replace("_", " ");
            let mut c = name.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        }
    }
}

pub fn get_packer_name(filename: &str) -> Option<&'static str> {
    match filename {
        s if s.contains("libjiagu.so") || s.contains("libprotectClass.so") => Some("360加固"),
        s if s.contains("libtupoke.so") || s.contains("libshell.so") => Some("腾讯乐固"),
        s if s.contains("libsecexe.so") || s.contains("libsecmain.so") => Some("梆梆安全"),
        s if s.contains("libexec.so") || s.contains("libijiami.so") => Some("爱加密"),
        s if s.contains("libnesec.so") || s.contains("libnh.so") => Some("网易易盾"),
        s if s.contains("libsgmain.so") => Some("阿里聚安全"),
        s if s.contains("libbaiduprotect.so") => Some("百度加固"),
        s if s.contains("libflutter.so") => Some("Flutter 框架"),
        s if s.contains("libreactnativejni.so") => Some("React Native"),
        s if s.contains("libunity.so") => Some("Unity3D"),
        _ => None,
    }
}

pub fn is_text_file(path: &str) -> bool {
    let ext = std::path::Path::new(path).extension().and_then(|s| s.to_str()).unwrap_or("");
    matches!(ext, "java" | "xml" | "smali" | "json" | "gradle" | "properties" | "txt")
}