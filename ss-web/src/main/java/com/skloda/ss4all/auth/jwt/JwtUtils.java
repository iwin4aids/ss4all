package com.skloda.ss4all.auth.jwt;

import ch.qos.logback.core.util.DatePatternToRegexUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import sun.util.calendar.CalendarUtils;

import java.util.Calendar;
import java.util.Date;

/**
 * Author: jiangkun
 * Date: Created on 2021/12/13 18:39
 * Description:
 */
public class JwtUtils {
    private static final long tokenExpiration = 24 * 60 * 60 * 1000;
    private static final String tokenSignKey = "123456";
    private static final String userRoleKey = "role";

    public static String createToken(String userName, String role) {
        return Jwts.builder().setSubject(userName)
                .claim(userRoleKey, role)
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpiration))
                .signWith(SignatureAlgorithm.HS512, tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();
    }

    public static String getUserNameFromToken(String token) {
        return Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
    }

    public static String getUserRoleFromToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody();
        return claims.get(userRoleKey).toString();
    }

    public static boolean isJwtTokenExpired(String token) throws Exception{
        Claims claims = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody();
        return claims.getExpiration().before(new Date());
    }

    public static void main(String[] args) throws Exception {
        System.out.println(isJwtTokenExpired("eyJhbGciOiJIUzUxMiIsInppcCI6IkdaSVAifQ.H4sIAAAAAAAAAKtWKi5NUrJSSkzJzcxT0lFKrShQsjI0M7Y0NTWwNDevBQAmAeRhIAAAAA.eGIWpREmiz-5s0VU3cPbW4mNMuwGLjqoaJ7y0FUdQWi_1hMt5co2rGECNNNIR04zms-DQ-AXrh0hNrQLQQh6fQ"));
    }

}
