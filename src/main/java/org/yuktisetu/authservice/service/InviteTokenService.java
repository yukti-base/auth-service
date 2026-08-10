package org.yuktisetu.authservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class InviteTokenService {
    private final StringRedisTemplate redis;
    private static final String PREFIX = "invite:";
    private static final Duration TTL = Duration.ofHours(72); // long enough for someone to check email over a weekend

    public String issue(Long userId) {
        String token = UUID.randomUUID().toString();
        redis.opsForValue().set(PREFIX + token, userId.toString(), TTL);
        return token;
    }

    /** Single-use: consumes and deletes atomically. Returns null if invalid/expired/already used. */
    public Long consume(String token) {
        String key = PREFIX + token;
        String userId = redis.opsForValue().getAndDelete(key);
        return userId == null ? null : Long.parseLong(userId);
    }
}
