package dev.keyshield.pdp.policy.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PolicyDecideResponse {
    private String tenantId;
    private String userId;
    private String site;

    // allow | mask | block
    private String action;
    private String reason;

    // 서버가 최종 적용한 detectTypes (정책상 override 가능)
    private List<String> detectTypes;

    private RestrictedStatus restricted;
}
