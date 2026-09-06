export const PAGE_ZOOM_LEVELS = Object.freeze([0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2]);

export function pageZoomCommand(event) {
  if (!event || event.defaultPrevented || event.isComposing || event.repeat || event.altKey) return null;
  if (Boolean(event.ctrlKey) === Boolean(event.metaKey)) return null;
  if (event.key === "0") return "reset";
  if (event.key === "+" || event.key === "=") return "increase";
  if (event.key === "-" || event.key === "_") return "decrease";
  return null;
}

export function nextPageZoom(current, command) {
  if (command === "reset") return 1;
  const nearest = PAGE_ZOOM_LEVELS.reduce((best, value) => (
    Math.abs(value - current) < Math.abs(best - current) ? value : best
  ));
  const index = PAGE_ZOOM_LEVELS.indexOf(nearest);
  if (command === "increase") return PAGE_ZOOM_LEVELS[Math.min(index + 1, PAGE_ZOOM_LEVELS.length - 1)];
  if (command === "decrease") return PAGE_ZOOM_LEVELS[Math.max(index - 1, 0)];
  return current;
}

export function installPageZoom(doc = document) {
  const root = doc.documentElement;
  const status = doc.createElement("p");
  status.id = "page-zoom-status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  status.style.cssText = "position:fixed;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0";
  doc.body.append(status);
  let current = 1;

  const apply = (command) => {
    const next = nextPageZoom(current, command);
    if (next === current && command !== "reset") return false;
    current = next;
    root.style.zoom = String(current);
    status.textContent = `Zoom ${Math.round(current * 100)}%`;
    return true;
  };

  doc.addEventListener("keydown", (event) => {
    const command = pageZoomCommand(event);
    if (!command) return;
    event.preventDefault();
    apply(command);
  });

  return { apply, get level() { return current; } };
}
