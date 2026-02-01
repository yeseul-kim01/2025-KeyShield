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
     * 붙여넣기 대상이 입력 가능한 영역인지 판단
     * @param {Element} el
     * @returns {boolean}
     */
    const isEditableTarget = (el) => {
      if (!el) return false;
  
      const tag = (el.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea") return true;
      if (el.isContentEditable) return true;
  
      const role = el.getAttribute?.("role");
      if (role === "textbox") return true;
  
      return false;
    };
  
    /**
     * 정규식 기반 secret 패턴 탐지
     * 원문은 반환/저장하지 않고 boolean 신호만 생성
     * @param {string} text
     * @returns {object} signals
     */
    const detectRegexSignals = (text) => {
      return {
        awsAccessKey: /AKIA[0-9A-Z]{16}/.test(text),
        jwtToken: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(compactText),
        pemHeader: /-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----/.test(text),
      };
    };

      /**
     * riskScore 계산 (0~100)
     * - 지금 단계에서는 "탐지 결과 요약" 목적
     * - 정책 결정은 다음 단계에서 PDP가 수행
     * @param {object} params
     * @param {number} params.length
     * @param {number} params.entropy
     * @param {object} params.regexSignals
     * @return {number} riskScore
     */
    const calcRiskScore = ({ length, entropy, regexSignals }) => {
        let score = 0;

        // 1) regex 기반 신호는 강한 가중치
        if (regexSignals.awsAccessKey) score += 60;
        if (regexSignals.jwtToken) score += 40;
        if (regexSignals.pemHeader) score += 80;

        // 2) entropy 기반 (대략적인 랜덤성 판단)
        // 일반 문장은 3~4 수준, 토큰류는 4.5~6 이상이 자주 나옴
        if (entropy >= 5.2) score += 30;
        else if (entropy >= 4.7) score += 20;
        else if (entropy >= 4.2) score += 10;

        // 3) 길이 보정 (너무 짧으면 위험도 낮게)
        if (length < 20) score -= 10;
        if (length > 200) score += 10;

        // 0~100 클램프
        score = Math.max(0, Math.min(100, score));
        return score;
    };


      /**
     * Shannon entropy 계산
     * - 텍스트의 "무작위성"을 수치로 계산
     * - base64/토큰/키 같은 문자열은 보통 entropy가 높음
     * 원문 저장/전송/출력 금지
     * @param {string} text
     * @returns {number} entropy
     */
    const calcShannonEntropy = (text) => {
        if (!text || text.length === 0) return 0;

        const freq = new Map();
        for (const ch of text) {
        freq.set(ch, (freq.get(ch) || 0) + 1);
        }

        let entropy = 0;
        const len = text.length;

        for (const [, count] of freq) {
        const p = count / len;
        entropy -= p * Math.log2(p);
        }

        // 소수점 3자리로 제한(로그/전송 시 크기 줄이기)
        return Math.round(entropy * 1000) / 1000;
    };


  
    log("content script injected", { url: location.href });
  
    document.addEventListener(
      "paste",
      (e) => {
        const target = e.target;
        if (!isEditableTarget(target)) return;
  
        const text = e.clipboardData?.getData("text") ?? "";
        if (!text) return;

        // 정규식 탐지 전 정규화: 줄바꿈/탭 → 공백, 연속 공백 정리
        const normalizedText = text
        .replace(/\s+/g, " ")
        .trim();

        // JWT 탐지용: 공백/줄바꿈 완전 제거 (dot 사이에 끼는 공백 제거 목적)
        const compactText = text.replace(/\s+/g, "");

  
        // 정규식 기반 탐지 시그널 생성
        const regexSignals = detectRegexSignals(normalizedText);

        // entropy 계산
        const entropy = calcShannonEntropy(normalizedText);

        // risk score 생성
        const riskScore = calcRiskScore({
            length: text.length,
            entropy,
            regexSignals,
        });

        // 원문 없이 요약 정보만 로그
        log("paste detected (signals + risk)", {
            url: location.href,
            length: text.length,
            entropy,
            riskScore,
            signals: regexSignals,
        });

      },
      true
    );
  })();
  