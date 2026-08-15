package org.yuktisetu.authservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.yuktisetu.authservice.config.LockoutProperties;
import org.yuktisetu.authservice.exception.AuthExceptions.AccountLockedException;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Slf4j
@Service
public class LoginAttemptService {

    private static final String KEY_PREFIX = "login_attempts:";

    private final StringRedisTemplate redis;
    private final LockoutProperties props;

    public LoginAttemptService(StringRedisTemplate redis, LockoutProperties props) {
        this.redis = redis;
        this.props = props;
    }

    /** Call before attempting password verification. Throws if currently locked out. */
    public void assertNotLocked(String email) {
        String key = KEY_PREFIX + email.toLowerCase();
        String raw = redis.opsForValue().get(key);
        int attempts = raw == null ? 0 : Integer.parseInt(raw);
        if (attempts >= props.getMaxAttempts()) {
            Long ttl = redis.getExpire(key);
            throw new AccountLockedException(ttl == null ? props.getLockoutWindowSeconds() : ttl);
        }
    }

    public void recordFailure(String email) {
        String key = KEY_PREFIX + email.toLowerCase();
        Long attempts = redis.opsForValue().increment(key);
        if (attempts != null && attempts == 1L) {
            redis.expire(key, Duration.ofSeconds(props.getLockoutWindowSeconds()));
        }
    }

    public void recordSuccess(String email) {
        redis.delete(KEY_PREFIX + email.toLowerCase());
    }
}
