package org.eli.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


/**
 * @ Description: 跨域配置
 * @ Author: zxhacker
 * @ CreateTime: 2024-04-29 20:04
 **/
@Configuration
public class CsrfConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowCredentials(true) // 允许发送Cookie
                .allowedOrigins("*") // 允许所有域名访问
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // 允许的HTTP方法
                .allowedHeaders("*") // 允许所有请求头
                .exposedHeaders("*"); // 暴露所有响应头

    }
}
