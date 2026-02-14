package dev.keyshield.pdp.policy.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
public class PolicyCurrentResponse {
    private String tenantId;
    private String userId;
    private String site;

    // allow | mask | block | detect-only
    private String action;

    // ["aws","jwt","pem"]
    private List<String> detectTypes;

    public PolicyCurrentResponse() {

    }
}
