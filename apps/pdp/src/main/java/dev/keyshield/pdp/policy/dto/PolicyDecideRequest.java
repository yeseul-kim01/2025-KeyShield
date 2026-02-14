package dev.keyshield.pdp.policy.dto;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class PolicyDecideRequest {
    private String tenantId;
    private String userId;
    private String site;

    // extension이 current에서 받아온 detectTypes를 그대로 넘김(서버 검증/보정 가능)
    private List<String> detectTypes;

    // signals: {"aws":true,"jwt":false,"pem":false}
    private Map<String, Boolean> signals;

    // 0~100
    private int riskScore;

    private double entropy;
    private int length;
}
