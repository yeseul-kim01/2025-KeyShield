package dev.keyshield.pdp.domain;

import java.util.HashMap;
import java.util.Map;

public class RiskAccumulator {

    public static class State {
        double score;
        long lastUpdatedMs;
        long restrictedUntilMs;
        String level; // NONE | SOFT | HARD
    }

    public static class Result {
        public final boolean active;
        public final String level;
        public final double score;
        public final long untilEpochMs;

        public Result(boolean active, String level, double score, long untilEpochMs) {
            this.active = active;
            this.level = level;
            this.score = score;
            this.untilEpochMs = untilEpochMs;
        }
    }

    // key: tenant:user:site
    private final Map<String, State> map = new HashMap<>();

    // 감쇠: half-life 10분 (점수가 10분마다 절반으로)
    private static final long HALF_LIFE_MS = 10 * 60 * 1000;

    // Restricted 기준(예시)
    private static final double SOFT_THRESHOLD = 180; // 누적 점수
    private static final double HARD_THRESHOLD = 320;

    // 제한 시간
    private static final long SOFT_RESTRICT_MS = 2 * 60 * 1000;   // 2분
    private static final long HARD_RESTRICT_MS = 10 * 60 * 1000;  // 10분

    public Result update(String tenantId, String userId, String site, int deltaScore) {
        long now = System.currentTimeMillis();
        String k = key(tenantId, userId, site);

        State s = map.get(k);
        if (s == null) {
            s = new State();
            s.score = 0;
            s.lastUpdatedMs = now;
            s.restrictedUntilMs = 0;
            s.level = "NONE";
            map.put(k, s);
        }

        // decay 적용
        long dt = Math.max(0, now - s.lastUpdatedMs);
        double decayFactor = Math.pow(0.5, (double) dt / (double) HALF_LIFE_MS);
        s.score = s.score * decayFactor + deltaScore;
        s.lastUpdatedMs = now;

        // 이미 restricted 중이면 active 유지
        if (now < s.restrictedUntilMs) {
            return new Result(true, s.level, s.score, s.restrictedUntilMs);
        }

        // 새로 restricted 판정
        if (s.score >= HARD_THRESHOLD) {
            s.level = "HARD";
            s.restrictedUntilMs = now + HARD_RESTRICT_MS;
            return new Result(true, s.level, s.score, s.restrictedUntilMs);
        }

        if (s.score >= SOFT_THRESHOLD) {
            s.level = "SOFT";
            s.restrictedUntilMs = now + SOFT_RESTRICT_MS;
            return new Result(true, s.level, s.score, s.restrictedUntilMs);
        }

        s.level = "NONE";
        s.restrictedUntilMs = 0;
        return new Result(false, "NONE", s.score, 0);
    }


    private String key(String tenantId, String userId, String site) {
        // key: tenant:user:site
        return tenantId + ":" + userId + ":" + site;
    }

}
