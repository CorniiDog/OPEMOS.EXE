const DOCUMENT_LIMIT = 1024 * 1024;
const statuses = new Set(["compatible", "invalid_target", "no_compatible_artifact", "resolver_error", "unsupported_target"]);

function displayText(value, limit = 2048) {
  if (value == null) return "Not provided";
  if (typeof value !== "string") throw new Error("Malformed compatibility preview response.");
  return value.length > limit ? `${value.slice(0, limit)}… (truncated for display)` : value;
}

// Presentation of the Rust-validated Core result only. No source selection,
// compatibility inference, network action, or activation is derived here.
export function presentCompatibilityPreview(preview) {
  const origins = {
    "unverified-document": "Unverified pasted document",
    "development-fixture": "Development fixture — non-production",
  };
  if (!preview || !Object.hasOwn(origins, preview.origin)) throw new Error("Unknown compatibility preview origin.");
  const result = preview.result;
  if (result?.schemaVersion !== 2 || !statuses.has(result.status) || !result.target) {
    throw new Error("Unsupported compatibility preview response.");
  }
  const rows = [
    ["Core status", result.status],
    ["SteamOS target", displayText(result.target.steamosVersion, 64)],
    ["Kernel target", displayText(result.target.kernelVersion, 255)],
    ["Architecture", displayText(result.target.architecture, 64)],
    ["Compatibility reported by Core", displayText(result.compatibility)],
    ["Reason", displayText(result.reason, 128)],
    ["Message", displayText(result.message)],
  ];
  if (result.publication) rows.push(
    ["Publication tag", displayText(result.publication.tag, 1024)],
    ["Published SteamOS", displayText(result.publication.steamosVersion, 64)],
    ["Published kernel", displayText(result.publication.kernelVersion, 255)],
    ["Published NVIDIA", displayText(result.publication.nvidiaVersion, 128)],
  );
  if (result.artifact) rows.push(
    ["Artifact name", displayText(result.artifact.name, 255)],
    ["Artifact trust reported by Core", displayText(result.artifact.trust?.classification)],
    ["Required verification", displayText(result.artifact.trust?.requiredVerification)],
  );
  if (result.nextAction) rows.push(
    ["Next action reported by Core", displayText(result.nextAction.kind)],
    ["Action architecture", displayText(result.nextAction.executionArchitecture, 64)],
    ["Kernel policy", displayText(result.nextAction.kernelPolicy, 64)],
  );
  return { origin: origins[preview.origin], rows };
}

export function createCompatibilityPreviewController(invoke, render) {
  let revision = 0;
  return {
    clear() {
      revision += 1;
      render({ phase: "empty" });
    },
    async inspect(request) {
      const current = ++revision;
      render({ phase: "loading" });
      try {
        if (request.source === "document" && (typeof request.document !== "string"
          || !request.document.trim() || new TextEncoder().encode(request.document).length > DOCUMENT_LIMIT)) {
          throw new Error("Paste a Core resolver JSON document no larger than 1 MiB.");
        }
        const response = await invoke("preview_core_compatibility", { request });
        if (current !== revision) return;
        render({ phase: "result", preview: presentCompatibilityPreview(response) });
      } catch (error) {
        if (current !== revision) return;
        render({ phase: "error", message: String(error?.message ?? error).slice(0, 2048) });
      }
    },
  };
}

export function installCompatibilityPreview(documentRef, invoke) {
  const get = (id) => documentRef.getElementById(id);
  const dialog = get("compatibility-dialog");
  const input = get("compatibility-document");
  const status = get("compatibility-status");
  const result = get("compatibility-result");
  const rows = get("compatibility-fields");
  const controller = createCompatibilityPreviewController(invoke, (state) => {
    dialog.setAttribute("aria-busy", String(state.phase === "loading"));
    result.hidden = state.phase !== "result";
    rows.replaceChildren();
    status.textContent = state.phase === "loading" ? "Checking document structure…"
      : state.phase === "error" ? state.message
      : state.phase === "result" ? state.preview.origin : "No result loaded.";
    if (state.phase !== "result") return;
    for (const [label, value] of state.preview.rows) {
      const row = documentRef.createElement("div");
      const term = documentRef.createElement("dt");
      const description = documentRef.createElement("dd");
      term.textContent = label;
      description.textContent = value;
      row.append(term, description);
      rows.append(row);
    }
  });
  get("compatibility-open").addEventListener("click", () => dialog.showModal());
  get("compatibility-close").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => { input.value = ""; controller.clear(); });
  // Native dialog owns focus/Tab/Escape; underlying settings shortcuts must not run.
  dialog.addEventListener("keydown", (event) => event.stopPropagation());
  get("compatibility-clear").addEventListener("click", () => { input.value = ""; controller.clear(); });
  input.addEventListener("input", () => controller.clear());
  get("compatibility-inspect").addEventListener("click", () => {
    void controller.inspect({ source: "document", document: input.value });
  });
  for (const [id, name] of [["compatibility-fixture-compatible", "compatible"], ["compatibility-fixture-no-artifact", "no-artifact"]]) {
    get(id).addEventListener("click", () => {
      input.value = "";
      void controller.inspect({ source: "fixture", name });
    });
  }
  controller.clear();
  return controller;
}
