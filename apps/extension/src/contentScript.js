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

    // 1) AWS Access Key ID 마스킹 (AKIA + 16 chars)
    maskedText = maskedText.replace(/AKIA[0-9A-Z]{16}/g, (match) => {
      masked.aws = true;

      // prefix는 유지, 나머지는 *로 치환 (총 길이 맞춰줌)
      const prefix = match.slice(0, 4); // "AKIA"
      const stars = "*".repeat(Math.max(0, match.length - prefix.length));
      return prefix + stars;
    });

    // 2) JWT 마스킹
    // - 문장 중간에 포함되어 있어도 통째로 치환
    maskedText = maskedText.replace(
      /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
      () => {
        masked.jwt = true;
        return "<REDACTED_JWT>";
      }
    );

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
   * 간단 토스트(페이지 내 오버레이)
   * - 원문 노출 금지
   * - 너무 자주 뜨지 않도록 중복 방지
   */
  const showToast = (() => {
    let lastToastAt = 0;
    let toastEl = null;

    const ensureEl = () => {
      if (toastEl && document.body.contains(toastEl)) return toastEl;

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

      document.documentElement.appendChild(toastEl);
      return toastEl;
    };

    return (message) => {
      const now = Date.now();
      // 600ms 이내 연타 방지
      if (now - lastToastAt < 600) return;
      lastToastAt = now;

      const el = ensureEl();
      el.textContent = message;

      // show
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
  
    // 2) JWT는 entropy까지 같이 본다 (오탐 방지)
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

      //토큰류 판별 compactText entropy
      const entropy = calcShannonEntropy(compactText);

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
      // debug용 전체 정보 출력 - 주석 처리
      // console.log("KeyShield Debug:", {
      //   regexSignals,
      //   entropy,
      //   riskScore,
      //   secretDetected,
      // });

      // past 이벤트 기본 동작 차단
      // if (secretDetected) {
      //   e.preventDefault();

      //   log("paste blocked (secret detected)", {
      //     url: location.href,
      //     length: compactText.length,
      //     entropy,
      //     riskScore,
      //     signals: regexSignals,
      //   });
      //   return;
      // }


      // Secret이 탐지된 경우 마스킹 처리 후 삽입
      // feat # 14 : 원본 paste 차단 + 마스킹 텍스트 삽입
      if (secretDetected) {
        // 원본 paste 차단
        e.preventDefault();
      
        // 마스킹 치환
        const { maskedText, masked } = maskSecretsInText(text);
      
        // input/textarea에 마스킹 텍스트 삽입
        const inserted = insertTextIntoInput(target, maskedText);
      
        log("paste masked (secret detected)", {
          url: location.href,
          inserted,
          length: maskedText.length, // 마스킹 결과 길이
          entropy,
          riskScore,
          masked, // {aws, jwt, pem}
          signals: regexSignals,
        });
      
        return;
      }
      

      // 디버깅용(원문 없음)
      log("paste allowed", {
        url: location.href,
        length: compactText.length,
        entropy,
        riskScore,
        signals: regexSignals,
      });
    },
    true
  );
})();
