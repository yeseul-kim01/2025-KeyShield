package dev.keyshield.pdp.policy.service;

import dev.keyshield.pdp.policy.dto.RestrictedStatus;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RedisRiskAccumulatorService {

    private static final String PREFIX = "ks:risk:";

    // decay 기준(half-life)
    private static final long HALF_LIFE_MS = 60_000; // 60초에 절반으로 감소(원하면 조정)

    // 임계치
    private static final double SOFT_THRESHOLD = 120.0;
    private static final double HARD_THRESHOLD = 220.0;

    // 제한 지속시간
    private static final long SOFT_RESTRICT_MS = 30_000;
    private static final long HARD_RESTRICT_MS = 90_000;

    // key TTL
    private static final long TTL_SEC = 24 * 60 * 60;

    private final StringRedisTemplate redis;
    private final DefaultRedisScript<String> script;

    public RedisRiskAccumulatorService(StringRedisTemplate redis) {
        this.redis = redis;
        this.script = new DefaultRedisScript<>();
        this.script.setResultType(String.class);
        this.script.setScriptText(LUA);
    }

    private String key(String tenantId, String userId, String site) {
        return PREFIX + tenantId + ":" + userId + ":" + site;
    }

    public RestrictedStatus update(String tenantId, String userId, String site, int riskScore) {
        long now = System.currentTimeMillis();
        String k = key(tenantId, userId, site);

        // ✅ Lua 스크립트 실행
        String out = redis.execute(
                script,
                List.of(k),
                String.valueOf(now),
                String.valueOf(riskScore),
                String.valueOf(HALF_LIFE_MS),
                String.valueOf(SOFT_THRESHOLD),
                String.valueOf(HARD_THRESHOLD),
                String.valueOf(SOFT_RESTRICT_MS),
                String.valueOf(HARD_RESTRICT_MS),
                String.valueOf(TTL_SEC)
        );

        // ✅ 결과 파싱 → RestrictedStatus 생성
        if (out == null || out.isBlank()) return RestrictedStatus.none();

        String[] parts = out.split("\\|");
        if (parts.length != 4) return RestrictedStatus.none();

        boolean active = "1".equals(parts[0]);

        RestrictedStatus.Level level;
        try {
            level = RestrictedStatus.Level.valueOf(parts[1]);
        } catch (Exception e) {
            level = RestrictedStatus.Level.NONE;
        }

        double score = safeDouble(parts[2]);
        long until = safeLong(parts[3]);

        if (!active) return RestrictedStatus.none(score);
        return RestrictedStatus.active(level, until, score);
    }

    private static double safeDouble(String v) {
        try { return Double.parseDouble(v); } catch (Exception e) { return 0.0; }
    }

    private static long safeLong(String v) {
        try { return Long.parseLong(v); } catch (Exception e) { return 0L; }
    }

    private static final String LUA = """
        local key = KEYS[1]

        local nowMs = tonumber(ARGV[1])
        local delta = tonumber(ARGV[2])
        local halfLifeMs = tonumber(ARGV[3])

        local softTh = tonumber(ARGV[4])
        local hardTh = tonumber(ARGV[5])
        local softRestrMs = tonumber(ARGV[6])
        local hardRestrMs = tonumber(ARGV[7])
        local ttlSec = tonumber(ARGV[8])

        local score = tonumber(redis.call('HGET', key, 'score') or '0')
        local last = tonumber(redis.call('HGET', key, 'last') or tostring(nowMs))
        local until = tonumber(redis.call('HGET', key, 'until') or '0')
        local level = redis.call('HGET', key, 'level') or 'NONE'

        local dt = nowMs - last
        if dt < 0 then dt = 0 end

        -- decay: score * (0.5 ^ (dt / halfLifeMs))
        local decay = math.pow(0.5, dt / halfLifeMs)
        local newScore = (score * decay) + delta

        local active = 0
        local newUntil = until
        local newLevel = level

        if nowMs < until then
          active = 1
        else
          -- 제한 종료 이후: 새 점수 기준으로 재평가
          if newScore >= hardTh then
            newLevel = 'HARD'
            newUntil = nowMs + hardRestrMs
            active = 1
          elseif newScore >= softTh then
            newLevel = 'SOFT'
            newUntil = nowMs + softRestrMs
            active = 1
          else
            newLevel = 'NONE'
            newUntil = 0
            active = 0
          end
        end

        redis.call('HSET', key, 'score', tostring(newScore))
        redis.call('HSET', key, 'last', tostring(nowMs))
        redis.call('HSET', key, 'until', tostring(newUntil))
        redis.call('HSET', key, 'level', newLevel)
        redis.call('EXPIRE', key, ttlSec)

        return tostring(active) .. '|' .. newLevel .. '|' .. tostring(newScore) .. '|' .. tostring(newUntil)
    """;
}
