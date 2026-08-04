package org.yuktisetu.authservice.service;


import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.yuktisetu.authservice.config.JwtProperties;
import org.yuktisetu.authservice.exception.AuthExceptions;

import java.time.Duration;
import java.util.UUID;

/**
 * Refresh tokens are opaque random values, not JWTs — they carry no information
 * of their own and are meaningless without a Redis lookup. That's deliberate:
 * it means a refresh token can be revoked instantly (delete the Redis key),
 * unlike a signed JWT which stays valid until it naturally expires.
 *
 * Rotation: every successful refresh deletes the token that was just used and
 * issues a brand new one. A refresh token is therefore single-use. If the same
 * token is presented twice, the second attempt fails — that's the signal that
 * a token was stolen and used by someone other than the legitimate holder.
 */
@Service
public class RefreshTokenService {

    private static final String KEY_PREFIX = "refresh:";

    private final StringRedisTemplate redis;
    private final JwtProperties jwtProperties;

    public RefreshTokenService(StringRedisTemplate redis, JwtProperties jwtProperties) {
        this.redis = redis;
        this.jwtProperties = jwtProperties;
    }

    public String issue(Long userId) {
        String token = UUID.randomUUID()+ "." + UUID.randomUUID();
        redis.opsForValue().set(
                KEY_PREFIX + token,
                userId.toString(),
                Duration.ofSeconds(jwtProperties.getRefreshTokenTtlSeconds())
        );
        return token;
    }

    /**
     * Validates and consumes the token in one step. Returns the owning userId.
     * Throws if the token is unknown/expired/already used.
     */
    public Long consume(String token) {
        String key = KEY_PREFIX + token;
        String userId = redis.opsForValue().get(key);
        if (userId == null) {
            throw new AuthExceptions.InvalidRefreshTokenException();
        }
        redis.delete(key);
        return Long.parseLong(userId);
    }

    /** Used on explicit logout, and should also be called on password change / admin-forced logout. */
    public void revoke(String token) {
        redis.delete(KEY_PREFIX + token);
    }

    /**
     * NOTE: this only revokes the one token presented. It does NOT revoke every
     * other active session/device for the user, because we're not tracking a
     * per-user index of issued tokens (that's a reasonable v2 addition if you
     * need "log out of all devices" — flagging it as a known gap, not solving
     * it here since you didn't ask for it and it changes the Redis key schema).
     */
}
