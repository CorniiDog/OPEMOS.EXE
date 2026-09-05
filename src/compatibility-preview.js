const DOCUMENT_LIMIT = 1024 * 1024;
const statuses = new Set(["compatible", "invalid_target", "no_compatible_artifact", "resolver_error", "unsupported_target"]);

function displayText(value, limit = 2048) {
  if (value == null) return "Not provided";
  if (typeof value !== "string") throw new Error("Malformed compatibility preview response.");
  return value.length > limit ? `${value.slice(0, limit)}… (truncated for display)` : value;
}

function generationIdentity(value) {
  if (!value || !Number.isSafeInteger(value.sequence) || value.sequence < 1
      || typeof value.generationId !== "string" || !value.generationId
      || value.generationId.length > 128
      || typeof value.manifestSha256 !== "string" || !/^[0-9a-f]{64}$/.test(value.manifestSha256)
      || Object.keys(value).some((key) => !["sequence", "generationId", "manifestSha256"].includes(key))) {
    throw new Error("Malformed generation status preview.");
  }
  return `#${value.sequence} · ${value.generationId} · ${value.manifestSha256}`;
}

function generationRows(preview) {
  const state = preview.generationState;
  if (state == null) return [];
  const fields = ["available", "selected", "active", "lastKnownGood"];
  if (preview.origin !== "development-fixture" || !Array.isArray(state.available)
      || state.available.length < 1 || state.available.length > 4
      || Object.keys(state).length !== fields.length
      || Object.keys(state).some((key) => !fields.includes(key))) {
    throw new Error("Unsupported generation status preview.");
  }
  const identityKey = (value) => JSON.stringify([value.sequence, value.generationId, value.manifestSha256]);
  const available = state.available.map((value) => [identityKey(value), generationIdentity(value)]);
  const availableKeys = new Set(available.map(([key]) => key));
  if (availableKeys.size !== available.length) throw new Error("Duplicate generation status preview.");
  const optional = (value) => {
    if (value == null) return "None";
    const displayed = generationIdentity(value);
    if (!availableKeys.has(identityKey(value))) throw new Error("Generation status is not available.");
    return displayed;
  };
  return [
    ["Available generations — development fixture", available.map(([, value]) => value).join("; ")],
    ["Selected generation — development fixture", optional(state.selected)],
    ["Active generation — development fixture", optional(state.active)],
    ["Last-known-good generation — development fixture", optional(state.lastKnownGood)],
  ];
}

// Presentation of the Rust-validated Core result only. No source selection,
// compatibility inference, network action, or activation is derived here.
export function presentCompatibilityPreview(preview) {
  const origins = {
    "unverified-document": "Unverified document",
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
    ["Exact-target support reported by Core", displayText(result.compatibility)],
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
  rows.push(...generationRows(preview));
  return { origin: origins[preview.origin], rows };
}

export function createCompatibilityPreviewController(invoke, render) {
  let revision = 0;
  async function inspect(makeRequest) {
    const current = ++revision;
    render({ phase: "loading" });
    try {
      const pending = makeRequest();
      const request = pending && typeof pending.then === "function" ? await pending : pending;
      if (current !== revision) return;
      if (request.source === "document" && (typeof request.document !== "string"
        || !request.document.trim() || new TextEncoder().encode(request.document).length > DOCUMENT_LIMIT)) {
        throw new Error("Choose or paste a Core resolver JSON document no larger than 1 MiB.");
      }
      const response = await invoke("preview_core_compatibility", { request });
      if (current !== revision) return;
      render({ phase: "result", preview: presentCompatibilityPreview(response) });
    } catch (error) {
      if (current !== revision) return;
      render({ phase: "error", message: String(error?.message ?? error).slice(0, 2048) });
    }
  }
  return {
    clear() {
      revision += 1;
      render({ phase: "empty" });
    },
    inspect(request) { return inspect(() => request); },
    inspectPath(path) {
      return inspect(() => {
        if (typeof path !== "string" || !path || path.length > 4096) {
          throw new Error("Choose an absolute local resolver JSON path.");
        }
        return { source: "file", path };
      });
    },
    fail(error) {
      revision += 1;
      render({ phase: "error", message: String(error?.message ?? error).slice(0, 2048) });
    },
    inspectFile(file) {
      return inspect(async () => {
        if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > DOCUMENT_LIMIT) {
          throw new Error("Choose a nonempty Core resolver JSON file no larger than 1 MiB.");
        }
        let document;
        try {
          const bytes = await file.slice(0, DOCUMENT_LIMIT + 1).arrayBuffer();
          if (bytes.byteLength !== file.size || bytes.byteLength > DOCUMENT_LIMIT) throw new Error();
          // Preserve a BOM rather than silently changing the Rust parser's input.
          document = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
        } catch {
          throw new Error("Could not read the selected file as UTF-8 JSON. Choose it again.");
        }
        return { source: "document", document };
      });
    },
  };
}

export function installCompatibilityPreview(documentRef, invoke, openFile = null) {
  const get = (id) => documentRef.getElementById(id);
  const dialog = get("compatibility-dialog");
  const input = get("compatibility-document");
  const fileOpen = get("compatibility-file-open");
  const openButton = get("compatibility-open");
  const closeButton = get("compatibility-close");
  const status = get("compatibility-status");
  const result = get("compatibility-result");
  const rows = get("compatibility-fields");
  const controller = createCompatibilityPreviewController(invoke, (state) => {
    dialog.setAttribute("aria-busy", String(state.phase === "loading"));
    result.hidden = state.phase !== "result";
    rows.replaceChildren();
    const statusText = state.phase === "loading" ? "Checking document structure…"
      : state.phase === "error" ? state.message
      : state.phase === "result" ? state.preview.origin : "No result loaded.";
    status.textContent = statusText;
    status.setAttribute("aria-label", statusText);
    if (state.phase !== "result") return;
    for (const [label, value] of state.preview.rows) {
      const row = documentRef.createElement("div");
      const term = documentRef.createElement("dt");
      const description = documentRef.createElement("dd");
      term.textContent = label;
      term.setAttribute("aria-label", label);
      description.textContent = value;
      description.setAttribute("aria-label", value);
      row.append(term, description);
      rows.append(row);
    }
  });
  fileOpen.addEventListener("click", () => {
    if (typeof openFile !== "function") {
      controller.fail(new Error("Native local-file selection is unavailable."));
      return;
    }
    void openFile().then((path) => {
      if (path == null) return;
      input.value = "";
      void controller.inspectPath(path);
    }, (error) => controller.fail(error));
  });
  openButton.addEventListener("click", () => { dialog.showModal(); closeButton.focus(); });
  closeButton.addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => {
    input.value = "";
    controller.clear();
    openButton.focus();
  });
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
