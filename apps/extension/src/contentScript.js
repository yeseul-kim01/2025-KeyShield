(() => {
  const LOG_PREFIX = "[KeyShield]";

  // PDP 서버 주소 
  // 1) window.__KEYSHIELD_PDP_URL__ (테스트/주입용)
  // 2) chrome.storage.local("ks.pdpBaseUrl")
  // 3) 없으면 null -> overlay + local fallback
  let PDP_BASE_URL = typeof window !== "undefined" ? window.__KEYSHIELD_PDP_URL__ : null;

  const log = (message, payload) => {
    if (payload) console.log(LOG_PREFIX, message, payload);
    else console.log(LOG_PREFIX, message);
  };

  /** -------------------------------------------
   * storage helpers (user/tenant 분리용)
   * ------------------------------------------- */
  const storageGet = (key) =>
    new Promise((resolve) => {
      try {
        chrome.storage.local.get([key], (r) => resolve(r?.[key]));
      } catch (_) {
        resolve(null);
      }
    });

  const getRuntimeIdentity = async () => {
    const tenantId = (await storageGet("ks.tenantId")) || "t-1";
    const userId = (await storageGet("ks.userId")) || "u-1";
    const pdpUrl = (await storageGet("ks.pdpBaseUrl")) || PDP_BASE_URL || null;
    PDP_BASE_URL = pdpUrl;
    return { tenantId, userId, pdpUrl };
  };

  /** -------------------------------------------
   * Secret masking (원문 저장/전송/로그 금지)
   * ------------------------------------------- */
  const maskSecretsInText = (rawText, enabledTypes = ["aws", "jwt", "pem"]) => {
    if (!rawText) return { maskedText: "", masked: { aws: false, jwt: false, pem: false } };

    let maskedText = rawText;
    const masked = { aws: false, jwt: false, pem: false };

    const has = (t) => enabledTypes.includes(t);

    if (has("aws")) {
      // 공백/개행 허용
      const AWS_ACCESS_KEY_FUZZY = /A\s*K\s*I\s*A(?:\s*[0-9A-Z]){16}/g;
      maskedText = maskedText.replace(AWS_ACCESS_KEY_FUZZY, () => {
        masked.aws = true;
        return "AKIA" + "*".repeat(16);
      });
    }

    if (has("jwt")) {
      const JWT_FUZZY = /eyJ[A-Za-z0-9_-]+(?:\s*\.\s*[A-Za-z0-9_-]+){2}/g;
      maskedText = maskedText.replace(JWT_FUZZY, () => {
        masked.jwt = true;
        return "<REDACTED_JWT>";
      });
    }

    if (has("pem")) {
      maskedText = maskedText.replace(
        /-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----[\s\S]*?-----END (RSA|EC|DSA)? ?PRIVATE KEY-----/g,
        () => {
          masked.pem = true;
          return "<REDACTED_PRIVATE_KEY>";
        }
      );
    }

    return { maskedText, masked };
  };

  /** -------------------------------------------
   * insert into input/textarea
   * ------------------------------------------- */
  const insertTextIntoInput = (el, text) => {
    try {
      const start = typeof el.selectionStart === "number" ? el.selectionStart : el.value.length;
      const end = typeof el.selectionEnd === "number" ? el.selectionEnd : el.value.length;
      el.setRangeText(text, start, end, "end");
      el.dispatchEvent(new Event("input", { bubbles: true }));
      return true;
    } catch (_) {
      return false;
    }
  };

  const isEditableTarget = (el) => {
    if (!el) return false;
    const tag = (el.tagName || "").toLowerCase();
    return tag === "input" || tag === "textarea";
  };

  /** -------------------------------------------
   * detect + score (detectTypes 기반 동적 적용)
   * ------------------------------------------- */
  const detectRegexSignals = (normalizedText, compactText, detectTypes) => {
    const has = (t) => (detectTypes || []).includes(t);

    return {
      awsAccessKey: has("aws") ? /AKIA[0-9A-Z]{16}/.test(compactText) : false,
      jwtToken: has("jwt") ? /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(compactText) : false,
      pemHeader: has("pem") ? /-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----/.test(normalizedText) : false,
    };
  };

  const calcShannonEntropy = (text) => {
    if (!text || text.length === 0) return 0;
    const freq = new Map();
    for (const ch of text) freq.set(ch, (freq.get(ch) || 0) + 1);

    let entropy = 0;
    const len = text.length;
    for (const [, count] of freq) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 1000) / 1000;
  };

  const sampleForEntropy = (s, max = 2000) => {
    if (s.length <= max) return s;
    const half = Math.floor(max / 2);
    return s.slice(0, half) + s.slice(-half);
  };

  const calcRiskScore = ({ length, entropy, regexSignals }) => {
    let score = 0;

    if (regexSignals.awsAccessKey) score += 60;
    if (regexSignals.jwtToken) score += 40;
    if (regexSignals.pemHeader) score += 80;

    if (entropy >= 5.2) score += 30;
    else if (entropy >= 4.7) score += 20;
    else if (entropy >= 4.2) score += 10;

    if (length < 20) score -= 10;
    if (length > 200) score += 10;

    return Math.max(0, Math.min(100, score));
  };

  const isSecretCandidate = ({ regexSignals, entropy, length }) => {
    if (length < 20) return false;

    if (regexSignals.awsAccessKey || regexSignals.pemHeader) return true;
    if (regexSignals.jwtToken && entropy >= 4.5) return true;

    return false;
  };

  /** -------------------------------------------
   * UI: toast + overlay
   * ------------------------------------------- */
  const showToast = (() => {
    let toastEl = null;
    let hideTimer = null;

    const ensureEl = () => {
      if (toastEl && document.documentElement.contains(toastEl)) return toastEl;

      toastEl = document.createElement("div");
      toastEl.setAttribute("data-keyshield-toast", "1");
      toastEl.style.cssText = `
        position: fixed;
        z-index: 2147483647;
        max-width: 360px;
        padding: 12px 14px;
        border-radius: 10px;
        background: rgba(17, 17, 17, 0.92);
        color: #fff;
        font-size: 13px;
        line-height: 1.35;
        box-shadow: 0 6px 18px rgba(0,0,0,0.25);
        opacity: 0;
        transform: translateY(6px);
        transition: opacity 160ms ease, transform 160ms ease;
        pointer-events: none;
        white-space: pre-line;
      `;
      (document.body || document.documentElement).appendChild(toastEl);
      return toastEl;
    };

    const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

    const positionAboveTarget = (el, target) => {
      if (!target || !target.getBoundingClientRect) {
        el.style.right = "16px";
        el.style.bottom = "16px";
        el.style.left = "auto";
        el.style.top = "auto";
        return;
      }

      const rect = target.getBoundingClientRect();
      const margin = 10;
      const viewportW = window.innerWidth;
      const viewportH = window.innerHeight;

      el.style.left = "0px";
      el.style.top = "0px";
      el.style.right = "auto";
      el.style.bottom = "auto";

      // 레이아웃 계산 위해 잠깐 렌더 상태 확보
      el.style.opacity = "0";
      el.style.transform = "translateY(6px)";

      const toastW = el.offsetWidth || 320;
      const toastH = el.offsetHeight || 48;

      const centerX = rect.left + rect.width / 2;
      let left = centerX - toastW / 2;
      let top = rect.top - toastH - margin;

      if (top < 8) top = rect.bottom + margin;

      left = clamp(left, 8, viewportW - toastW - 8);
      top = clamp(top, 8, viewportH - toastH - 8);

      el.style.left = `${Math.round(left)}px`;
      el.style.top = `${Math.round(top)}px`;
    };

    return (target, message, { durationMs = 4500 } = {}) => {
      const el = ensureEl();
      el.textContent = message;

      positionAboveTarget(el, target);

      el.style.opacity = "1";
      el.style.transform = "translateY(0)";
      requestAnimationFrame(() => {
        el.style.opacity = "1";
        el.style.transform = "translateY(0)";
      });

      if (hideTimer) clearTimeout(hideTimer);
      hideTimer = setTimeout(() => {
        if (!toastEl) return;
        toastEl.style.opacity = "0";
        toastEl.style.transform = "translateY(6px)";
      }, durationMs);
    };
  })();

  const showSystemOverlay = (() => {
    let overlayEl = null;
    let isVisible = false;

    const createOverlay = () => {
      overlayEl = document.createElement("div");
      overlayEl.setAttribute("data-keyshield-overlay", "1");
      overlayEl.style.cssText = `
        position: fixed;
        inset: 0;
        z-index: 2147483646;
        background: rgba(0, 0, 0, 0.35);
        backdrop-filter: blur(4px);
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      `;

      const modal = document.createElement("div");
      modal.style.cssText = `
        min-width: 320px;
        max-width: 420px;
        padding: 24px;
        border-radius: 16px;
        background: #ffffff;
        color: #111;
        box-shadow: 0 20px 50px rgba(0,0,0,0.25);
        text-align: center;
      `;

      modal.innerHTML = `
        <div style="font-size:18px; font-weight:700; margin-bottom:6px;">KeyShield</div>
        <div id="ks-overlay-message" style="font-size:14px; line-height:1.45; margin-bottom:14px;">
          서버 점검 중입니다.
        </div>
        <button id="ks-overlay-close"
          style="padding:8px 14px; border-radius:10px; border:none; background:#111; color:#fff; cursor:pointer;">
          확인
        </button>
      `;

      overlayEl.appendChild(modal);
      (document.body || document.documentElement).appendChild(overlayEl);

      overlayEl.querySelector("#ks-overlay-close").onclick = () => {
        overlayEl.style.display = "none";
        isVisible = false;
      };
    };

    const show = (message) => {
      if (isVisible) return;
      if (!overlayEl) createOverlay();

      const msgEl = overlayEl.querySelector("#ks-overlay-message");
      if (msgEl) msgEl.textContent = message;

      overlayEl.style.display = "flex";
      isVisible = true;
    };

    return show;
  })();

  /** -------------------------------------------
   * PDP calls (current + decide)
   * - 원문 텍스트 절대 전송 X
   * - AbortController로 타임아웃
   * ------------------------------------------- */
  let hasShownPdpDownOverlay = false;

  const fetchJsonWithTimeout = async (url, options = {}, timeoutMs = 900) => {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...options, signal: controller.signal });
      if (!res.ok) throw new Error("http_not_ok");
      return await res.json();
    } finally {
      clearTimeout(t);
    }
  };

  const fetchPolicyCurrent = async ({ tenantId, userId, site }) => {
    const { pdpUrl } = await getRuntimeIdentity();
    if (!pdpUrl) return null;

    const url =
      `${pdpUrl}/policy/current?tenantId=${encodeURIComponent(tenantId)}` +
      `&userId=${encodeURIComponent(userId)}` +
      `&site=${encodeURIComponent(site)}`;

    try {
      return await fetchJsonWithTimeout(url, {}, 900);
    } catch (_) {
      return null;
    }
  };

  const postPolicyDecide = async ({ tenantId, userId, site, detectTypes, signals, riskScore, entropy, length }) => {
    const { pdpUrl } = await getRuntimeIdentity();
    if (!pdpUrl) return null;

    const url = `${pdpUrl}/policy/decide`;
    try {
      return await fetchJsonWithTimeout(
        url,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tenantId,
            userId,
            site,
            detectTypes,
            signals,
            riskScore,
            entropy,
            length,
          }),
        },
        1100
      );
    } catch (_) {
      return null;
    }
  };

  /** -------------------------------------------
   * Local fallback enforcement (서버 죽으면)
   * ------------------------------------------- */
  const decideEnforcementLocal = ({ secretDetected, regexSignals, riskScore }) => {
    if (!secretDetected) return { action: "allow", reason: "no_secret" };
    if (regexSignals.pemHeader) return { action: "mask", reason: "pem_private_key" };
    if (regexSignals.awsAccessKey) return { action: "mask", reason: "aws_access_key" };
    if (regexSignals.jwtToken) return { action: "mask", reason: "jwt_token" };
    if (riskScore >= 70) return { action: "mask", reason: "high_risk_string" };
    return { action: "allow", reason: "low_confidence" };
  };

  log("content script injected", { url: location.href });

  document.addEventListener(
    "paste",
    async (e) => {
      const target = e.target;
      if (!isEditableTarget(target)) return;

      const text = e.clipboardData?.getData("text") ?? "";
      if (!text) return;

      const site = location.hostname;
      const { tenantId, userId, pdpUrl } = await getRuntimeIdentity();

      // 1) 서버 정책 먼저 조회 (allow면 탐지 자체 skip)
      const current = await fetchPolicyCurrent({ tenantId, userId, site });

      if (!pdpUrl && !hasShownPdpDownOverlay) {
        showSystemOverlay("현재 정책 서버를 설정 중입니다.\n(확장 설정/배포 단계)\n잠시 후 다시 시도해주세요.");
        hasShownPdpDownOverlay = true;
      }

      if (!current) {
        // 서버 죽었거나 아직 미구현: overlay 1회만
        if (!hasShownPdpDownOverlay) {
          showSystemOverlay("정책 서버와 연결할 수 없습니다.\n백엔드 서버를 점검 중입니다.");
          hasShownPdpDownOverlay = true;
        }
      } else {
        if (current.action === "allow") {
          log("paste allowed (pdp allow)", { site, tenantId, userId });
          return;
        }
      }

      // 2) detectTypes는 서버 기준(없으면 기본값)
      const detectTypes = current?.detectTypes?.length ? current.detectTypes : ["aws", "jwt", "pem"];

      // 3) 탐지/entropy/score 계산 (detectTypes 기반)
      const normalizedText = text.replace(/\s+/g, " ").trim();
      const compactText = text.replace(/\s+/g, "");

      const regexSignals = detectRegexSignals(normalizedText, compactText, detectTypes);

      // entropy는 jwt만 계산(성능)
      const entropy = detectTypes.includes("jwt") && regexSignals.jwtToken
        ? calcShannonEntropy(sampleForEntropy(compactText, 2000))
        : 0;

      const riskScore = calcRiskScore({
        length: compactText.length,
        entropy,
        regexSignals,
      });

      const secretDetected = isSecretCandidate({
        regexSignals,
        entropy,
        length: compactText.length,
      });

      // 4) 서버에 riskScore/시그널 보고 → 중앙 누적/감쇠 + restricted 적용 후 최종 action
      const decideRes = await postPolicyDecide({
        tenantId,
        userId,
        site,
        detectTypes,
        signals: {
          aws: regexSignals.awsAccessKey,
          jwt: regexSignals.jwtToken,
          pem: regexSignals.pemHeader,
        },
        riskScore,
        entropy,
        length: compactText.length,
      });

      let action, reason, restricted;

      if (decideRes?.action) {
        action = decideRes.action;
        reason = decideRes.reason || "pdp_decide";
        restricted = decideRes.restricted || null;

        // restricted 상태면 사용자에게 명확히 알려주기(UX)
        if (restricted?.active) {
          showToast(
            target,
            `KeyShield: 보안 제한 상태입니다.\n(${restricted.level}) 잠시 후 다시 시도해주세요.`,
            { durationMs: 6500 }
          );
        }
      } else {
        // 서버 실패 → 로컬 fallback
        const local = decideEnforcementLocal({ secretDetected, regexSignals, riskScore });
        action = local.action;
        reason = local.reason;
      }

      // enforce
      if (action === "allow") {
        log("paste allowed", {
          site,
          tenantId,
          userId,
          reason,
          riskScore,
          signals: regexSignals,
          restricted,
        });
        return;
      }

      e.preventDefault();

      if (action === "block") {
        showToast(target, "KeyShield: 민감 정보로 의심되어 붙여넣기가 차단되었습니다.", { durationMs: 5500 });
        log("paste blocked", { site, tenantId, userId, reason, riskScore, signals: regexSignals, restricted });
        return;
      }

      if (action === "mask") {
        const { maskedText, masked } = maskSecretsInText(text, detectTypes);
        const inserted = insertTextIntoInput(target, maskedText);

        showToast(target, "KeyShield: 민감 정보로 의심되어 일부가 마스킹 처리되었습니다.", { durationMs: 4500 });

        log("paste masked", {
          site,
          tenantId,
          userId,
          inserted,
          reason,
          masked,
          riskScore,
          signals: regexSignals,
          restricted,
        });
        return;
      }
    },
    true
  );
})();
