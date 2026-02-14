package dev.keyshield.pdp.domain;

import lombok.Getter;

import java.util.List;

@Getter
public class SitePolicy {
    public String action;          // allow | mask | block | detect-only
    public List<String> detectTypes;
    public boolean blockPem;       // pem은 block 강제 여부

    public SitePolicy(String action, List<String> detectTypes, boolean blockPem) {
        this.action = action;
        this.detectTypes = detectTypes;
        this.blockPem = blockPem;
    }
}
