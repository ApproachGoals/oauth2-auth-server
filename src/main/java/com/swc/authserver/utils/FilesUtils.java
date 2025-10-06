package com.swc.authserver.utils;

import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class FilesUtils {

    public Path resolveConfigPath(String fileName) {
        // Linux 路径优先
        Path linuxPath = Paths.get("/etc/config/auth-service/"+fileName);
        if (Files.exists(linuxPath)) return linuxPath;

        // Windows 路径
        Path windowsPath = Paths.get("c:/config/auth-service/"+fileName);
        if (Files.exists(windowsPath)) return windowsPath;

        // fallback: application.yml 配置的路径
        return Paths.get(fileName);
    }
}
