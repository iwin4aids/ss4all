package com.skloda.ss4all.utils;

import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

public class HttpUtils {

    public static boolean isAjaxRequest(HttpServletRequest request) {
        return "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));
    }

    public static boolean hasBringToken(HttpServletRequest request) {
        return !StringUtils.isEmpty(request.getHeader("Authorization"));
    }
}
