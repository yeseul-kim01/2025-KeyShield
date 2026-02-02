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
    // - 예: AKIA1234... → AKIA****************
    maskedText = maskedText.replace(/AKIA[0-9A-Z]{16}/g, (match) => {
      masked.aws = true;

      // prefix는 유지, 나머지는 *로 치환 (총 길이 맞춰줌)
      const prefix = match.slice(0, 4); // "AKIA"
      const stars = "*".repeat(Math.max(0, match.length - prefix.length));
      return prefix + stars;
    });

    // 2) JWT 마스킹
    // - 문장 중간에 포함되어 있어도 통째로 치환
    // - 예: eyJxxx.yyy.zzz → <REDACTED_JWT>
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
   * 최종 Secret 판정
   * - regex 신호 + entropy 기준을 함께 사용
   * - 원문 저장/전송/로그 금지
   */
  const isSecretCandidate = ({ regexSignals, entropy, length }) => {
    const hasStrongSignal =
      regexSignals.awsAccessKey || regexSignals.jwtToken || regexSignals.pemHeader;

    if (!hasStrongSignal) return false;
    if (length < 20) return false;

    // 기본 컷(추후 정책화)
    return entropy >= 4.7;
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

      if (secretDetected) {
        e.preventDefault();

        log("paste blocked (secret detected)", {
          url: location.href,
          length: compactText.length,
          entropy,
          riskScore,
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
