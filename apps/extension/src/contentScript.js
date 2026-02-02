(() => {
  const LOG_PREFIX = "[KeyShield]";

  /**
   * 간단 로그 헬퍼
   * - 원문 출력 금지
   * @param {string} message
   * @param {object} [payload]
   * @return {void}
   */
  const log = (message, payload) => {
    if (payload) console.log(LOG_PREFIX, message, payload);
    else console.log(LOG_PREFIX, message);
  };


    /**
   * (임시) 도메인 allowlist
   * - TODO: 다음 이슈에서 chrome.storage 기반으로 교체
   */
  const isAllowlistedDomain = (host) => {
    // 예: 내부 개발환경/로컬은 허용하고 싶다 이런거
    const allow = new Set(["localhost", "127.0.0.1"]);
    return allow.has(host);
  };


    /**
   * Secret 마스킹 유틸
   * - 원문을 저장/전송/로그 출력하지 않음
   * - 문자열 내 Secret 패턴만 치환하여 "마스킹된 텍스트"를 반환
   * - 이 함수는 "치환 로직만" 담당 (paste 이벤트 처리와 분리)
   *
   * @param {string} rawText
   * @returns {{ maskedText: string, masked: { aws: boolean, jwt: boolean, pem: boolean } }}
   */
  const maskSecretsInText = (rawText) => {
    if (!rawText) {
      return { maskedText: "", masked: { aws: false, jwt: false, pem: false } };
    }

    let maskedText = rawText;

    const masked = {
      aws: false,
      jwt: false,
      pem: false,
    };

    // 1) AWS Access Key ID 마스킹 (공백/개행 허용)
    const AWS_ACCESS_KEY_FUZZY = /A\s*K\s*I\s*A(?:\s*[0-9A-Z]){16}/g;

    maskedText = maskedText.replace(AWS_ACCESS_KEY_FUZZY, () => {
      masked.aws = true;
      return "AKIA" + "*".repeat(16);
    });

    // 2) JWT 마스킹 (공백/개행 허용)
    const JWT_FUZZY = /eyJ[A-Za-z0-9_-]+(?:\s*\.\s*[A-Za-z0-9_-]+){2}/g;

    maskedText = maskedText.replace(JWT_FUZZY, () => {
      masked.jwt = true;
      return "<REDACTED_JWT>";
    });


    // 3) PEM Private Key 마스킹
    // - 멀티라인 블록 전체를 치환
    // - BEGIN/END 헤더가 있을 때만 동작
    maskedText = maskedText.replace(
      /-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----[\s\S]*?-----END (RSA|EC|DSA)? ?PRIVATE KEY-----/g,
      () => {
        masked.pem = true;
        return "<REDACTED_PRIVATE_KEY>";
      }
    );

    return { maskedText, masked };
  };


    /**
   * input/textarea에 텍스트를 커서 위치에 삽입
   * - setRangeText를 우선 사용 (가장 깔끔)
   * @param {HTMLInputElement|HTMLTextAreaElement} el
   * @param {string} text
   * @returns {boolean} 성공 여부
   */
  const insertTextIntoInput = (el, text) => {
    try {
      const start = typeof el.selectionStart === "number" ? el.selectionStart : el.value.length;
      const end = typeof el.selectionEnd === "number" ? el.selectionEnd : el.value.length;

      // setRangeText는 selection을 유지/이동 옵션 지정 가능
      el.setRangeText(text, start, end, "end");

      // input 이벤트를 발생시켜 React/Vue 등 프레임워크 바인딩도 반영되게
      el.dispatchEvent(new Event("input", { bubbles: true }));
      return true;
    } catch (err) {
      return false;
    }
  };


  /**
   * 붙여넣기 대상이 입력 가능한 영역인지 판단
   * (Out of Scope: contenteditable, role=textbox)
   * @param {Element} el
   * @returns {boolean}
   */
  const isEditableTarget = (el) => {
    if (!el) return false;

    const tag = (el.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea") return true;

    // Out of scope는 false 처리
    return false;
  };

  /**
   * 정규식 기반 secret 패턴 탐지
   * @param {string} normalizedText 공백 정리된 텍스트
   * @param {string} compactText 공백 제거된 텍스트 (JWT/키 탐지 안정화)
   * @return {{awsAccessKey:boolean, jwtToken:boolean, pemHeader:boolean}}
   */
  const detectRegexSignals = (normalizedText, compactText) => {
    return {
      // AWS Access Key ID (AKIA로 시작하는 20자 키)
      awsAccessKey: /AKIA[0-9A-Z]{16}/.test(compactText),

      // JWT: 줄바꿈/공백이 있어도 탐지되도록 compactText 사용
      jwtToken: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(compactText),

      // PEM Private Key Header
      pemHeader: /-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----/.test(normalizedText),
    };
  };

  /**
   * Shannon entropy 계산
   * - base64/토큰/키 같은 문자열은 보통 entropy가 높음
   * - 원문 저장/전송/출력 금지
   * @param {string} text
   * @returns {number}
   */
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

  /**
   * riskScore 계산 (0~100)
   * - 지금 단계에서는 "탐지 결과 요약" 목적
   * - 정책 결정은 다음 단계에서 PDP가 수행
   */
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


    /**
   * 사이트 정책 읽기
   * - TODO: 다음 이슈에서 chrome.storage.sync/local로 구현
   */
  const getSitePolicy = (host) => {
    return {
      mode: "mask", // "allow" | "mask" | "block" | "detect-only"
      maskTypes: { aws: true, jwt: true, pem: true },
    };
  };




    /**
   * 정책 결정
   * - 지금 이슈 범위에서는 기본 정책만 고정
   * - TODO: 다음 이슈에서 site별 설정 / detect-only / allowlist 등을 붙일 자리
   *
   * @param {{secretDetected:boolean, regexSignals:any, riskScore:number, entropy:number, length:number}} ctx
   * @returns {{ action: "allow" | "mask" | "block", reason: string }}
   */
  const decideEnforcement = (ctx) => {
    const { secretDetected, regexSignals, riskScore } = ctx;
    if (isAllowlistedDomain(location.hostname)) return { action: "allow", reason: "allowlisted_domain" };
    if (!secretDetected) return { action: "allow", reason: "no_secret" };

    // 강한 시그널은 무조건 mask
    if (regexSignals.pemHeader) return { action: "mask", reason: "pem_private_key" }; 

    if (regexSignals.awsAccessKey) return { action: "mask", reason: "aws_access_key" };
    if (regexSignals.jwtToken) return { action: "mask", reason: "jwt_token" };

    // 엔트로피만 높은 경우는 마스킹 대신 경고
    if (riskScore >= 70) return { action: "mask", reason: "high_risk_string" };

    return { action: "allow", reason: "low_confidence" };
  };



    /**
   * 간단 토스트(페이지 내 오버레이)
   * - 원문 노출 금지
   * - 너무 자주 뜨지 않도록 중복 방지
   */
    const showToast = (() => {
      let lastToastAt = 0;
      let toastEl = null;
      let lastMsg = "";
    
      const ensureEl = () => {
        if (toastEl && document.documentElement.contains(toastEl)) return toastEl;
    
        toastEl = document.createElement("div");
        toastEl.setAttribute("data-keyshield-toast", "1");
        toastEl.style.cssText = `
          position: fixed;
          z-index: 2147483647;
          right: 16px;
          bottom: 16px;
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
    
        // body가 있으면 body로, 없으면 html로
        (document.body || document.documentElement).appendChild(toastEl);
        return toastEl;
      };
    
      return (message) => {
        const now = Date.now();
    
        // 같은 메시지 연타 막기
        if (now - lastToastAt < 600 && message === lastMsg) return;
    
        lastToastAt = now;
        lastMsg = message;
    
        const el = ensureEl();
        el.textContent = message;
    
        // show (rAF가 안 먹을 때 대비해서 2단계)
        el.style.opacity = "1";
        el.style.transform = "translateY(0)";
        requestAnimationFrame(() => {
          el.style.opacity = "1";
          el.style.transform = "translateY(0)";
        });

    
        // hide
        setTimeout(() => {
          if (!toastEl) return;
          toastEl.style.opacity = "0";
          toastEl.style.transform = "translateY(6px)";
        }, 2200);
      };
    })();
    

  /**
   * 최종 Secret 판정
   * - regex 신호 + entropy 기준을 함께 사용
   * - 원문 저장/전송/로그 금지
   */
  const isSecretCandidate = ({ regexSignals, entropy, length }) => {
    // 너무 짧으면 컷
    if (length < 20) return false;
  
    // 1) 강한 정규식 시그널은 entropy 무시
    if (
      regexSignals.awsAccessKey ||
      regexSignals.pemHeader
    ) {
      return true;
    }
  
    // 2) JWT는 entropy (오탐 방지)
    if (regexSignals.jwtToken && entropy >= 4.5) {
      return true;
    }
  
    return false;
  };
  

  log("content script injected", { url: location.href });

  document.addEventListener(
    "paste",
    (e) => {
      const target = e.target;
      if (!isEditableTarget(target)) return;
  
      const text = e.clipboardData?.getData("text") ?? "";
      if (!text) return;
  
      // 정규화
      const normalizedText = text.replace(/\s+/g, " ").trim();
      const compactText = text.replace(/\s+/g, "");
  
      const regexSignals = detectRegexSignals(normalizedText, compactText);
      
      // REFACT: settimeout 방지를 위해 조건부로 변경
      // entropy 계산 최적화
      // JWT 토큰이 있을 때만 계산
      const sampleForEntropy = (s, max = 2000) => {
        if (s.length <= max) return s;
        const half = Math.floor(max / 2);
        return s.slice(0, half) + s.slice(-half);
      };
      
      const entropy = regexSignals.jwtToken
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
  
      // 정책 결정
      const { action, reason } = decideEnforcement({
        secretDetected,
        regexSignals,
        riskScore,
        entropy,
        length: compactText.length,
      });
  
      // allow: 그냥 통과
      if (action === "allow") {
        log("paste allowed", {
          url: location.href,
          length: compactText.length,
          entropy,
          riskScore,
          reason,
          signals: regexSignals,
        });
        return;
      }
  
      // block / mask: 원본 paste 차단
      e.preventDefault();
  
      // block
      if (action === "block") {
        showToast("KeyShield: 민감 정보로 의심되어 붙여넣기가 차단되었습니다.");
        log("paste blocked (secret detected)", {
          url: location.href,
          length: compactText.length,
          entropy,
          riskScore,
          reason,
          signals: regexSignals,
        });
        return;
      }
  
      // mask
      if (action === "mask") {
        const { maskedText, masked } = maskSecretsInText(text);
        const inserted = insertTextIntoInput(target, maskedText);
  
        showToast("KeyShield: 민감 정보로 의심되어 일부가 마스킹 처리되었습니다.");
  
        log("paste masked (secret detected)", {
          url: location.href,
          inserted,
          length: maskedText.length,
          entropy,
          riskScore,
          reason,
          masked, // {aws, jwt, pem}
          signals: regexSignals,
        });
        return;
      }
    },
    true
  );  
})();
