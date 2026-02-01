(() => {
    const isEditableTarget = (el) => {
      if (!el) return false;
      const tag = (el.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea") return true;
      if (el.isContentEditable) return true;
      return false;
    };
  
    document.addEventListener(
      "paste",
      (e) => {
        const target = e.target;
        if (!isEditableTarget(target)) return;
  
        const text = e.clipboardData?.getData("text") ?? "";
        if (!text) return;
  
        console.log("[KeyShield] paste detected", {
          url: location.href,
          length: text.length,
          sample: text.slice(0, 12) + (text.length > 12 ? "..." : "")
        });
      },
      true // capture 단계에서 먼저 감지
    );
  })();
  