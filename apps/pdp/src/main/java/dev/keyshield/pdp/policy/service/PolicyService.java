package dev.keyshield.pdp.policy.service;

import dev.keyshield.pdp.policy.dto.PolicyResponse;
import dev.keyshield.pdp.policy.store.InMemoryPolicyStore;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PolicyService {

    private final InMemoryPolicyStore store;

    public PolicyResponse getCurrentPolicy(String tenantId, String site) {

        String action = store.getAction(tenantId, site);

        return new PolicyResponse(
                tenantId,
                site,
                action,
                store.defaultDetectTypes()
        );
    }
}
