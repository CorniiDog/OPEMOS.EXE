const KEY_ALIASES = new Map([
  ["Esc", "Escape"],
  ["Spacebar", " "],
  ["Left", "ArrowLeft"],
  ["Right", "ArrowRight"],
  ["Up", "ArrowUp"],
  ["Down", "ArrowDown"],
]);

export function normalizeKeyboardKey(value) {
  const key = KEY_ALIASES.get(String(value ?? "")) || String(value ?? "");
  return key.length === 1 ? key.toLowerCase() : key;
}

export function isEditableKeyboardTarget(target) {
  if (!target || target.nodeType !== 1) return false;
  if (target.isContentEditable) return true;
  return ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}

export function isMacKeyboardPlatform(platform = globalThis.navigator?.platform || "") {
  return /(?:mac|iphone|ipad|ipod)/i.test(String(platform));
}

function modifierMatches(actual, expected = false) {
  return expected === "any" || actual === expected;
}

export function matchesKeyboardBinding(event, binding, platform) {
  if (!event || event.isComposing || event.defaultPrevented) return false;
  if (event.repeat && !binding.allowRepeat) return false;
  if (normalizeKeyboardKey(event.key) !== normalizeKeyboardKey(binding.key)) return false;
  if (!binding.allowInEditable && isEditableKeyboardTarget(event.target)) return false;

  const accelerator = binding.accelerator ?? false;
  const primaryPressed = isMacKeyboardPlatform(platform) ? event.metaKey : event.ctrlKey;
  const secondaryPressed = isMacKeyboardPlatform(platform) ? event.ctrlKey : event.metaKey;
  if (accelerator === "either") {
    if (!event.ctrlKey && !event.metaKey) return false;
  } else if (!modifierMatches(primaryPressed, accelerator)
      || !modifierMatches(secondaryPressed, binding.secondary ?? false)) {
    return false;
  }
  return modifierMatches(event.shiftKey, binding.shift ?? false)
    && modifierMatches(event.altKey, binding.alt ?? false);
}

export function installKeyboardBindings(bindings, {
  target = document,
  platform = globalThis.navigator?.platform || "",
} = {}) {
  const handler = (event) => {
    for (const binding of bindings) {
      if (binding.when && !binding.when(event)) continue;
      if (!matchesKeyboardBinding(event, binding, platform)) continue;
      if (binding.preventDefault !== false) event.preventDefault();
      if (binding.stopPropagation) event.stopPropagation();
      binding.run(event);
      break;
    }
  };
  target.addEventListener("keydown", handler);
  return () => target.removeEventListener("keydown", handler);
}

export function keepKeyboardFocusInside(event, container, documentRef = document) {
  const controls = [...container.querySelectorAll(
    "button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex='-1'])",
  )].filter((control) => control.getClientRects().length > 0 && control.getAttribute("aria-hidden") !== "true");
  if (!controls.length) return false;
  const first = controls[0];
  const last = controls.at(-1);
  if (event.shiftKey && documentRef.activeElement === first) {
    last.focus();
    return true;
  }
  if (!event.shiftKey && documentRef.activeElement === last) {
    first.focus();
    return true;
  }
  return false;
}

export function selectKeyboardRegionContents(element, {
  documentRef = document,
  selection = globalThis.getSelection?.(),
} = {}) {
  if (!element || !selection) return false;
  const range = documentRef.createRange();
  range.selectNodeContents(element);
  selection.removeAllRanges();
  selection.addRange(range);
  return true;
}
