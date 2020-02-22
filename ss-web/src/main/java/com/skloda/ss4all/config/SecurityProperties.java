package com.skloda.ss4all.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SecurityProperties {

    @Value("${spring.security.login-page.url:/login}")
    private String loginPage;

    @Value("${spring.security.userpwd-login.processurl:/login}")
    private String loginProcessUrl;

    @Value("${spring.security.web.ignore.patterns}")
    private String webIgnorePatterns;

    @Value("${spring.security.csrf.ignore.patterns}")
    private String csrfIgnorePatterns;

    @Value("${spring.security.ip-login.processurl:/ipVerify}")
    private String ipLoginProcessUrl;

    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    public String getLoginProcessUrl() {
        return loginProcessUrl;
    }

    public void setLoginProcessUrl(String loginProcessUrl) {
        this.loginProcessUrl = loginProcessUrl;
    }

    public String getWebIgnorePatterns() {
        return webIgnorePatterns;
    }

    public void setWebIgnorePatterns(String webIgnorePatterns) {
        this.webIgnorePatterns = webIgnorePatterns;
    }

    public String getCsrfIgnorePatterns() {
        return csrfIgnorePatterns;
    }

    public void setCsrfIgnorePatterns(String csrfIgnorePatterns) {
        this.csrfIgnorePatterns = csrfIgnorePatterns;
    }

    public String getIpLoginProcessUrl() {
        return ipLoginProcessUrl;
    }

    public void setIpLoginProcessUrl(String ipLoginProcessUrl) {
        this.ipLoginProcessUrl = ipLoginProcessUrl;
    }
}
