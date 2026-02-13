package dev.keyshield.pdp.policy.controller;

import dev.keyshield.pdp.policy.dto.PolicyResponse;
import dev.keyshield.pdp.policy.service.PolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class PolicyController {

    private final PolicyService policyService;

    @GetMapping("/policy/current")
    public PolicyResponse currentPolicy(
            @RequestParam String tenantId,
            @RequestParam String site
    ) {
        return policyService.getCurrentPolicy(tenantId, site);
    }
}
