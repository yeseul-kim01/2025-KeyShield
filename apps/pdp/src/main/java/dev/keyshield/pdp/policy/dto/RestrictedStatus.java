package dev.keyshield.pdp.policy.dto;

import lombok.Builder;
import lombok.Setter;

@Builder
@Setter
public class RestrictedStatus {
    public enum Level { NONE, SOFT, HARD }

    public final boolean active;
    public final Level level;
    public final long untilEpochMs;
    public final double score;

    public RestrictedStatus(boolean active, Level level, long untilEpochMs, double score) {
        this.active = active;
        this.level = level;
        this.untilEpochMs = untilEpochMs;
        this.score = score;
    }

    public static RestrictedStatus none() {
        return new RestrictedStatus(false, Level.NONE, 0L, 0.0);
    }

    public static RestrictedStatus none(double score) {
        return new RestrictedStatus(false, Level.NONE, 0L, score);
    }

    public static RestrictedStatus active(Level level, long untilEpochMs, double score) {
        return new RestrictedStatus(true, level, untilEpochMs, score);
    }

}
