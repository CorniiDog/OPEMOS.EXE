export function installWindowDrag(windowHandle) {
  const dragRegion = document.querySelector(".window-drag-region");
  if (!dragRegion) return;

  dragRegion.addEventListener("pointerdown", (event) => {
    if (!event.isPrimary || event.button !== 0) return;
    event.preventDefault();
    void windowHandle.startDragging().catch(() => {});
  });
}
