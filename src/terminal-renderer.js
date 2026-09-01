const ANSI_COLORS = ["#111827", "#ef4444", "#22c55e", "#eab308", "#3b82f6", "#d946ef", "#06b6d4", "#d1d5db"];
const ANSI_BRIGHT_COLORS = ["#6b7280", "#ff7070", "#6ee7a0", "#fde047", "#7da6ff", "#f08cff", "#67e8f9", "#ffffff"];

export function normalizeTerminalText(text) {
  return text
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]/g, "");
}

export function ansi256Color(index) {
  if (index < 8) return ANSI_COLORS[index];
  if (index < 16) return ANSI_BRIGHT_COLORS[index - 8];
  if (index < 232) {
    const value = index - 16;
    const levels = [0, 95, 135, 175, 215, 255];
    return `rgb(${levels[Math.floor(value / 36)]},${levels[Math.floor(value / 6) % 6]},${levels[value % 6]})`;
  }
  const gray = 8 + (index - 232) * 10;
  return `rgb(${gray},${gray},${gray})`;
}

export function freshAnsiState() {
  return { color: "", background: "", bold: false };
}

export function appendAnsiText(parent, text, state) {
  const pattern = /\x1b\[([0-?]*)([ -/]*)([@-~])/g;
  let offset = 0;
  const appendChunk = (chunk) => {
    if (!chunk) return;
    if (!state.color && !state.background && !state.bold) {
      parent.append(document.createTextNode(chunk));
      return;
    }
    const span = document.createElement("span");
    span.textContent = chunk;
    if (state.color) span.style.color = state.color;
    if (state.background) span.style.backgroundColor = state.background;
    if (state.bold) span.style.fontWeight = "700";
    parent.append(span);
  };
  for (const match of text.matchAll(pattern)) {
    appendChunk(text.slice(offset, match.index));
    offset = match.index + match[0].length;
    if (match[3] !== "m" || match[2]) continue;
    const codes = match[1] === "" ? [0] : match[1].split(";").map(Number);
    for (let index = 0; index < codes.length; index += 1) {
      const code = codes[index];
      if (code === 0) Object.assign(state, freshAnsiState());
      else if (code === 1) state.bold = true;
      else if (code === 22) state.bold = false;
      else if (code >= 30 && code <= 37) state.color = ANSI_COLORS[code - 30];
      else if (code >= 90 && code <= 97) state.color = ANSI_BRIGHT_COLORS[code - 90];
      else if (code === 39) state.color = "";
      else if (code >= 40 && code <= 47) state.background = ANSI_COLORS[code - 40];
      else if (code >= 100 && code <= 107) state.background = ANSI_BRIGHT_COLORS[code - 100];
      else if (code === 49) state.background = "";
      else if ((code === 38 || code === 48) && codes[index + 1] === 5) {
        const color = ansi256Color(codes[index + 2]);
        if (code === 38) state.color = color; else state.background = color;
        index += 2;
      } else if ((code === 38 || code === 48) && codes[index + 1] === 2) {
        const color = `rgb(${codes[index + 2]},${codes[index + 3]},${codes[index + 4]})`;
        if (code === 38) state.color = color; else state.background = color;
        index += 4;
      }
    }
  }
  appendChunk(text.slice(offset));
}
