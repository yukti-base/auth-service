package org.yuktisetu.authservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Setter
@Getter
@ConfigurationProperties(prefix = "yuktisetu.jwt")
public class JwtProperties {

    private String privateKeyPath;
    private long accessTokenTtlSeconds;
    private long refreshTokenTtlSeconds;
    private String issuer;

}
