package dev.keyshield.pdp.policy.dto;

import java.util.Set;

public record PolicyResponse(
        String tenantId,
        String site,
        String action,          // allow | mask | block
        Set<String> detectTypes // aws, jwt, pem
) {
}
