package dev.keyshield.pdp.policy.dto;

import lombok.Data;

import java.util.List;

@Data
public class PolicyUpsertRequest {
    private String tenantId;
    private String userId;  // 특정 유저 정책이면 값, 전체 공통이면 "*"
    private String site;    // 특정 도메인이면 값, 전체면 "*"

    // allow | mask | block | detect-only
    private String action;

    // ["aws","jwt","pem"]
    private List<String> detectTypes;
}
