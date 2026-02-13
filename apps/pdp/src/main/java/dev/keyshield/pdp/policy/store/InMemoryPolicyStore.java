package dev.keyshield.pdp.policy.store;

import dev.keyshield.pdp.policy.dto.PolicyResponse;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Component
public class InMemoryPolicyStore {

    // tenant → 기본 정책
    private final Map<String, String> tenantDefaultAction = new HashMap<>();

    // tenant → site → action
    private final Map<String, Map<String, String>> sitePolicies = new HashMap<>();

    public InMemoryPolicyStore() {
        // 기본 샘플 데이터
        tenantDefaultAction.put("t-1", "mask");

        Map<String, String> siteMap = new HashMap<>();
        siteMap.put("github.com", "mask");
        siteMap.put("notion.so", "allow");

        sitePolicies.put("t-1", siteMap);
    }

    public String getAction(String tenantId, String site) {
        Map<String, String> siteMap = sitePolicies.getOrDefault(tenantId, Map.of());

        return siteMap.getOrDefault(
                site,
                tenantDefaultAction.getOrDefault(tenantId, "mask")
        );
    }

    public PolicyResponse.MaskTypes defaultMaskTypes() {
        return new PolicyResponse.MaskTypes(true, true, true);
    }
}
