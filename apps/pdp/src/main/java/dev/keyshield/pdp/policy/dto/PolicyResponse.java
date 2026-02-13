package dev.keyshield.pdp.policy.dto;

public record PolicyResponse(
        String tenantId,
        String site,
        String action,          // allow | mask | block | detect-only
        MaskTypes maskTypes
) {
    public record MaskTypes(boolean aws, boolean jwt, boolean pem) {}
}
