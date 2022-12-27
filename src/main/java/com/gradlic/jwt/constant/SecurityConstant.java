package com.gradlic.jwt.constant;

public class SecurityConstant {
    public static final long EXPIRATION_TIME = 432_000_000; // 5 days expressed in millisecond
    public static final String TOKEN_HEADER = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token can not be verified";
    public static final String GET_ARRAYS_LLC = "Get Arrays, LLC";
    public static final String ARRAYS_ADMINISTRATION = "User management portal";
    public static final String AUTHORITIES = "authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to login  first to access this page";
    public static final String ACCESS_DENIED_MESSAGE = "You do not have permission to access this page";
    public static final String OPTIONS_HTTP_METHODS = "OPTIONS";
    public static final String[] PUBLIC_URLS = {"/users/login", "/users/register", "/users/resetpassword/**", "/users/image/**"};


}
