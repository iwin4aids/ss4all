package com.skloda.ss4all.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    //spring security国际化相关类都实现了spring的MessageSourceAware接口
    //故定义一个名为messageSource的bean会自动加载你的国际化资源文件
    @Bean(name = "messageSource")
    public ReloadableResourceBundleMessageSource getMessageResource() {
        ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
        messageSource.setBasename("classpath:messages");
        return messageSource;
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("index");//可不配，themyleaf默认首页
        registry.addViewController("/login").setViewName("login");
    }

}
