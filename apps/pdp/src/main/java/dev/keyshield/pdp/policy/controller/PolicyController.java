package dev.keyshield.pdp.policy.controller;

import dev.keyshield.pdp.policy.dto.PolicyCurrentResponse;
import dev.keyshield.pdp.policy.dto.PolicyDecideRequest;
import dev.keyshield.pdp.policy.dto.PolicyDecideResponse;
import dev.keyshield.pdp.policy.dto.PolicyUpsertRequest;
import dev.keyshield.pdp.policy.service.PolicyService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/policy")
public class PolicyController {

    private final PolicyService policyService;

    public PolicyController(PolicyService policyService) {
        this.policyService = policyService;
    }

    @GetMapping("/current")
    public PolicyCurrentResponse current(
            @RequestParam String tenantId,
            @RequestParam(required = false, defaultValue = "anonymous") String userId,
            @RequestParam String site
    ) {
        return policyService.current(tenantId, userId, site);
    }

    @PostMapping("/decide")
    public PolicyDecideResponse decide(@RequestBody PolicyDecideRequest req) {
        return policyService.decide(req);
    }

    @PostMapping("/upsert")
    public void upsert(@RequestBody PolicyUpsertRequest req) {
        policyService.upsert(req);
    }
}
