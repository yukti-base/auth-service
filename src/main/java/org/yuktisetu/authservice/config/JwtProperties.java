package org.yuktisetu.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "yuktisetu.jwt")
public class JwtProperties {

    private String privateKeyPath;
    private String publicKeyPath;
    private long accessTokenTtlSeconds;
    private long refreshTokenTtlSeconds;
    private String issuer;

    public String getPrivateKeyPath() { return privateKeyPath; }
    public void setPrivateKeyPath(String privateKeyPath) { this.privateKeyPath = privateKeyPath; }

    public String getPublicKeyPath() { return publicKeyPath; }
    public void setPublicKeyPath(String publicKeyPath) { this.publicKeyPath = publicKeyPath; }

    public long getAccessTokenTtlSeconds() { return accessTokenTtlSeconds; }
    public void setAccessTokenTtlSeconds(long accessTokenTtlSeconds) { this.accessTokenTtlSeconds = accessTokenTtlSeconds; }

    public long getRefreshTokenTtlSeconds() { return refreshTokenTtlSeconds; }
    public void setRefreshTokenTtlSeconds(long refreshTokenTtlSeconds) { this.refreshTokenTtlSeconds = refreshTokenTtlSeconds; }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
}
