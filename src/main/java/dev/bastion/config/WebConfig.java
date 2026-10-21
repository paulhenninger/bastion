package dev.bastion.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final HandlerInterceptor adminMfaInterceptor;

    public WebConfig(@org.springframework.beans.factory.annotation.Qualifier("adminMfaInterceptor")
                     HandlerInterceptor adminMfaInterceptor) {
        this.adminMfaInterceptor = adminMfaInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(adminMfaInterceptor).addPathPatterns("/api/v1/admin/**");
    }
}
