package org.yuktisetu.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "yuktisetu.login-lockout")
public class LockoutProperties {

    private int maxAttempts;
    private long lockoutWindowSeconds;

    public int getMaxAttempts() { return maxAttempts; }
    public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }

    public long getLockoutWindowSeconds() { return lockoutWindowSeconds; }
    public void setLockoutWindowSeconds(long lockoutWindowSeconds) { this.lockoutWindowSeconds = lockoutWindowSeconds; }
}
