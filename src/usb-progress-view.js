export function formatUsbProgressBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = -1;
  do { value /= 1024; unit += 1; } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
}

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
    ? `${formatBytes(progress.bytesCompleted)} of ${formatBytes(progress.bytesTotal)} processed.`
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
