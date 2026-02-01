(() => {
    const LOG_PREFIX = "[KeyShield]";
  
    const log = (message, payload) => {
      if (payload) console.log(LOG_PREFIX, message, payload);
      else console.log(LOG_PREFIX, message);
    };
  
    const isEditableTarget = (el) => {
      if (!el) return false;
  
      const tag = (el.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea") return true;
      if (el.isContentEditable) return true;
  
      const role = el.getAttribute?.("role");
      if (role === "textbox") return true;
  
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
  
        log("paste detected", {
          url: location.href,
          length: text.length,
          sample: text.slice(0, 12) + (text.length > 12 ? "..." : "")
        });
      },
      true
    );
  })();
  