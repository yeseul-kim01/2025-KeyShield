package dev.keyshield.pdp.policy.repos;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.keyshield.pdp.domain.SitePolicy;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;

@Repository
public class RedisPolicyRepository {

    private static final Duration TTL = Duration.ofDays(30);
    private static final String PREFIX = "ks:policy:";

    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper;

    public RedisPolicyRepository(StringRedisTemplate redis, ObjectMapper objectMapper) {
        this.redis = redis;
        this.objectMapper = objectMapper;
    }

    private String key(String tenantId, String userId, String site) {
        return PREFIX + tenantId + ":" + userId + ":" + site;
    }

    public void upsert(String tenantId, String userId, String site, SitePolicy policy) {
        try {
            String json = objectMapper.writeValueAsString(policy);
            redis.opsForValue().set(key(tenantId, userId, site), json, TTL);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("policy_serialize_failed", e);
        }
    }

    /**
     * 조회 우선순위:
     * 1) tenant:user:site
     * 2) tenant:user:*
     * 3) tenant:*:site
     * 4) tenant:*:*
     */
    public SitePolicy findEffective(String tenantId, String userId, String site) {
        SitePolicy p;

        p = get(tenantId, userId, site);
        if (p != null) return p;

        p = get(tenantId, userId, "*");
        if (p != null) return p;

        p = get(tenantId, "*", site);
        if (p != null) return p;

        p = get(tenantId, "*", "*");
        if (p != null) return p;

        return null;
    }

    private SitePolicy get(String tenantId, String userId, String site) {
        String json = redis.opsForValue().get(key(tenantId, userId, site));
        if (json == null || json.isBlank()) return null;

        try {
            return objectMapper.readValue(json, SitePolicy.class);
        } catch (Exception e) {
            return null;
        }
    }
}
