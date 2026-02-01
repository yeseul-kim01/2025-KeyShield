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
        jwtToken: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(text),
        pemHeader: /-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----/.test(text),
      };
    };
  
    log("content script injected", { url: location.href });
  
    document.addEventListener(
      "paste",
      (e) => {
        const target = e.target;
        if (!isEditableTarget(target)) return;
  
        const text = e.clipboardData?.getData("text") ?? "";
        if (!text) return;
  
        // 정규식 기반 탐지 시그널 생성
        const regexSignals = detectRegexSignals(text);
  
        // 원문 없이 요약 정보만 로그
        log("paste detected (regex signals)", {
          url: location.href,
          length: text.length,
          signals: regexSignals,
        });
      },
      true
    );
  })();
  