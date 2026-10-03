export function renderUsbWriteProgressView(displays, progress, formatBytes) {
  const phase = progress?.phase
    ? progress.phase.replace(/(^|-)([a-z])/g, (_match, separator, letter) => `${separator}${letter.toUpperCase()}`)
    : "Revalidating";
  const hasBytes = Number.isSafeInteger(progress?.bytesCompleted)
    && Number.isSafeInteger(progress?.bytesTotal)
    && progress.bytesTotal > 0;
  const ratio = hasBytes ? progress.bytesCompleted / progress.bytesTotal : null;
  const percent = ratio === null ? "Working…" : `${(ratio * 100).toFixed(1)}%`;
  const detail = hasBytes
    ? `${progress.message} ${formatBytes(progress.bytesCompleted)} of ${formatBytes(progress.bytesTotal)}.`
    : "Revalidating the exact image and removable drive.";
  for (const display of displays) {
    display.container.classList.remove("hidden");
    display.phase.textContent = phase;
    display.percent.textContent = percent;
    display.detail.textContent = detail;
    if (ratio === null) {
      display.bar.removeAttribute("value");
    } else {
      display.bar.value = ratio * 100;
    }
  }
}
