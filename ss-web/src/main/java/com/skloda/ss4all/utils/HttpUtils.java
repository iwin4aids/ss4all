package com.skloda.ss4all.utils;

import javax.servlet.http.HttpServletRequest;

public class HttpUtils {

    public static boolean isAjaxRequest(HttpServletRequest request) {
        return "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));
    }
}
