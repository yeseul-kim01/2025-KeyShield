package dev.keyshield.pdp.policy.service;

import dev.keyshield.pdp.domain.PolicyStore;
import dev.keyshield.pdp.domain.SitePolicy;
import dev.keyshield.pdp.policy.dto.PolicyCurrentResponse;
import dev.keyshield.pdp.policy.dto.PolicyDecideRequest;
import dev.keyshield.pdp.policy.dto.PolicyDecideResponse;
import dev.keyshield.pdp.policy.dto.PolicyUpsertRequest;
import dev.keyshield.pdp.policy.dto.RestrictedStatus;
import dev.keyshield.pdp.policy.repos.RedisPolicyRepository; // ✅ 여기만 고치면 됨
import org.springframework.stereotype.Service;

@Service
public class PolicyService {

    private final RedisPolicyRepository policyRepo;
    private final RedisRiskAccumulatorService riskAccumulator;

    // Redis 장애 시 fallback (로컬 기본 정책)
    private final PolicyStore localFallback = new PolicyStore();

    public PolicyService(RedisPolicyRepository policyRepo, RedisRiskAccumulatorService riskAccumulator) {
        this.policyRepo = policyRepo;
        this.riskAccumulator = riskAccumulator;
    }

    public PolicyCurrentResponse current(String tenantId, String userId, String site) {
        SitePolicy policy = resolvePolicy(tenantId, userId, site);

        PolicyCurrentResponse res = new PolicyCurrentResponse();
        res.setTenantId(tenantId);
        res.setSite(site);
        res.setAction(policy.getAction());
        res.setDetectTypes(policy.getDetectTypes());
        return res;
    }

    public PolicyDecideResponse decide(PolicyDecideRequest req) {
        SitePolicy policy = resolvePolicy(req.getTenantId(), req.getUserId(), req.getSite());

        // 중앙 누적(증가/감쇠) + restricted 판단
        RestrictedStatus restricted = riskAccumulator.update(
                req.getTenantId(),
                req.getUserId(),
                req.getSite(),
                req.getRiskScore()
        );

        // 지금 단계에서는 “정책 action” 그대로 반환
        PolicyDecideResponse res = new PolicyDecideResponse();
        res.setTenantId(req.getTenantId());
        res.setUserId(req.getUserId());
        res.setSite(req.getSite());
        res.setAction(policy.getAction());
        res.setDetectTypes(policy.getDetectTypes());
        res.setRestricted(restricted);
        return res;
    }

    public void upsert(PolicyUpsertRequest req) {
        String action = req.getAction();

        // blockPem: 요청에 필드가 없으면 기본 false
        boolean blockPem = false;

        SitePolicy policy = new SitePolicy(
                action,
                req.getDetectTypes(),
                blockPem
        );

        policyRepo.upsert(req.getTenantId(), req.getUserId(), req.getSite(), policy);
    }


    private SitePolicy resolvePolicy(String tenantId, String userId, String site) {
        try {
            SitePolicy fromRedis = policyRepo.findEffective(tenantId, userId, site);
            if (fromRedis != null) return fromRedis;
        } catch (Exception ignored) {
            // Redis가 죽었거나 연결 안되면 fallback
        }
        return localFallback.getPolicy(tenantId, userId, site);
    }
}
