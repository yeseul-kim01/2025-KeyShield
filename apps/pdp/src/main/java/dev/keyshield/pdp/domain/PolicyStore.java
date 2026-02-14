package dev.keyshield.pdp.domain;

import java.util.*;

public class PolicyStore {

    // key: tenantId:userId:site
    private final Map<String, SitePolicy> store = new HashMap<>();

    public PolicyStore() {
        // u-1: 기본 mask + aws/jwt/pem
        seed("t-1", "u-1", "*", new SitePolicy("mask", List.of("aws","jwt","pem"), false));

        // u-2: github는 allow, 나머지는 mask
        seed("t-1", "u-2", "github.com", new SitePolicy("allow", List.of(), false));
        seed("t-1", "u-2", "*", new SitePolicy("mask", List.of("aws","jwt","pem"), false));

        // u-3: pem은 block 강제, 나머지는 mask
        seed("t-1", "u-3", "*", new SitePolicy("mask", List.of("aws","jwt","pem"), true));

        // u-4: detect-only (탐지만 하고 allow로 내려줌)
        seed("t-1", "u-4", "*", new SitePolicy("detect-only", List.of("aws","jwt","pem"), false));
    }

    private void seed(String tenantId, String userId, String site, SitePolicy policy) {
        store.put(key(tenantId, userId, site), policy);
    }

    public SitePolicy getPolicy(String tenantId, String userId, String site) {
        SitePolicy exact = store.get(key(tenantId, userId, site));
        if (exact != null) return exact;

        SitePolicy wildcard = store.get(key(tenantId, userId, "*"));
        if (wildcard != null) return wildcard;

        // default
        return new SitePolicy("mask", List.of("aws","jwt","pem"), false);
    }

    private String key(String tenantId, String userId, String site) {
        return tenantId + ":" + userId + ":" + site;
    }
}
