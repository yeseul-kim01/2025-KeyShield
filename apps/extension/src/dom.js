export function isEditableTarget(el) {
    if (!el) return false;
  
    const tag = (el.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea") return true;
  
    // contenteditable
    if (el.isContentEditable) return true;
  
    // 일부 사이트는 role="textbox"를 씀
    const role = el.getAttribute?.("role");
    if (role === "textbox") return true;
  
    return false;
  }
  