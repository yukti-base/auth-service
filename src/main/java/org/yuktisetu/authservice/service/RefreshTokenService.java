package org.yuktisetu.authservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.yuktisetu.authservice.config.JwtProperties;
import org.yuktisetu.authservice.exception.AuthExceptions;

import java.time.Duration;
import java.util.Set;
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
 *
 * Two Redis key shapes, kept in step by every method here:
 *
 *   refresh:{token}      -> "{userId}"   (the token itself, TTL = refresh TTL)
 *   refresh:user:{id}    -> SET of that user's live tokens
 *
 * The per-user index is what makes {@link #revokeAllForUser(Long)} possible.
 * Without it there is no way to find a given person's sessions, which meant an
 * admin could deactivate someone's role and that person would keep refreshing a
 * valid session for the full 14-day refresh TTL. Any new write path MUST touch
 * both keys or the index drifts.
 */
@Slf4j
@Service
public class RefreshTokenService {

    private static final String KEY_PREFIX = "refresh:";
    private static final String USER_INDEX_PREFIX = "refresh:user:";

    private final StringRedisTemplate redis;
    private final JwtProperties jwtProperties;

    public RefreshTokenService(StringRedisTemplate redis, JwtProperties jwtProperties) {
        this.redis = redis;
        this.jwtProperties = jwtProperties;
    }

    public String issue(Long userId) {
        String token = UUID.randomUUID() + "." + UUID.randomUUID();
        Duration ttl = Duration.ofSeconds(jwtProperties.getRefreshTokenTtlSeconds());

        redis.opsForValue().set(KEY_PREFIX + token, userId.toString(), ttl);

        // Index the token under its owner, and push the index's own expiry out
        // to match the newest token in it. The index is a convenience structure,
        // never the source of truth: a stale member whose refresh:{token} key
        // has already expired is harmless, since consume() still fails on the
        // missing token key.
        String indexKey = USER_INDEX_PREFIX + userId;
        redis.opsForSet().add(indexKey, token);
        redis.expire(indexKey, ttl);

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
            log.warn("Refresh token consumption failed: token unknown, expired, or already used");
            throw new AuthExceptions.InvalidRefreshTokenException();
        }
        redis.delete(key);
        redis.opsForSet().remove(USER_INDEX_PREFIX + userId, token);
        return Long.parseLong(userId);
    }

    /** Used on explicit logout, and should also be called on password change / admin-forced logout. */
    public void revoke(String token) {
        String key = KEY_PREFIX + token;
        String userId = redis.opsForValue().get(key);
        redis.delete(key);
        if (userId != null) {
            redis.opsForSet().remove(USER_INDEX_PREFIX + userId, token);
            log.info("Logout: refresh token revoked for userId={}", userId);
        } else {
            log.warn("Logout called with an unknown or already-expired refresh token");
        }
    }

    /**
     * Kills every live session for one person, on every device, immediately.
     *
     * Called whenever that person's authority changes underneath them — role
     * deactivation, soft delete, hard delete. After this, their next refresh
     * fails and they must log in again, which re-issues an access token built
     * from their current role assignments rather than the ones they held when
     * they last logged in.
     *
     * Deliberately NOT called on ordinary role *creation*: gaining a role does
     * not make an existing session dangerous, and forcing a re-login there would
     * be pure friction.
     *
     * The already-issued access token still lives out its remaining TTL (15
     * minutes at most). That window is accepted policy for role changes; for
     * anything where 15 minutes genuinely matters, the caller should also mark
     * the account SUSPENDED so the login path refuses it.
     *
     * @return how many tokens were revoked, for the audit log.
     */
    public long revokeAllForUser(Long userId) {
        String indexKey = USER_INDEX_PREFIX + userId;
        Set<String> tokens = redis.opsForSet().members(indexKey);
        if (tokens == null || tokens.isEmpty()) {
            redis.delete(indexKey);
            return 0L;
        }
        tokens.forEach(t -> redis.delete(KEY_PREFIX + t));
        redis.delete(indexKey);
        log.info("All refresh tokens revoked for userId={}, count={}", userId, tokens.size());
        return tokens.size();
    }
}
