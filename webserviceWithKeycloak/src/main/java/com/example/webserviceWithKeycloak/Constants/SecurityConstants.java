package com.example.webserviceWithKeycloak.Constants;

public final class SecurityConstants {

    public static final String AUTH_LOGIN_URL = "/api/authenticate";

    // Signing key for HS512 algorithm
    // You can use the page http://www.allkeysgenerator.com/ to generate all kinds of keys
    public static final String JWT_SECRET = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm6sVrsI3wd8CGT8x54RuAgY408zu5k1U5d1IJIAz4AQQz2Z2OXga3uX67+b7enLiuBwHgSnKSUXk+Pvi/NtPz1QhMSoM0YwtsxTM0KMl5utv2/4OaJeO3gw20+JcvfB/IVKYPjqSaKZSliRGci6ke7/6B3sEBAA3vKyA9KqmQ79YnGkZVGPi1V55vgFKBpJQGgNo/2eB4m6jhUbW57pUt4MgeYymahzFjHXdPqeQKU594Jf41/q3mQEvuf5tDVKMkROFEeCZGiDn0HTves70q7KUiqIVnpsAQcRNFHCwWAoOSOgZwDpZ++3kxu1wdEoYYsAOk0pTO77s0R16KQCCawIDAQAB";    										 

    // JWT token defaults
    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String TOKEN_TYPE = "JWT";
    public static final String TOKEN_ISSUER = "secure-api";
    public static final String TOKEN_AUDIENCE = "secure-app";

    private SecurityConstants() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }
}