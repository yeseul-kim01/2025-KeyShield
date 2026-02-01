import { isEditableTarget } from "./dom.js";
import { log } from "./logger.js";

(function init() {
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
    true // capture: 페이지 스크립트보다 먼저 감지
  );

  log("content script injected", { url: location.href });
})();
