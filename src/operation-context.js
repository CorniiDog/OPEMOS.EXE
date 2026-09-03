export function operationContextMatches(expected, current) {
  if (!expected || !current || typeof expected !== "object" || typeof current !== "object") {
    return false;
  }
  return Object.keys(expected).every((key) => expected[key] === current[key]);
}

export function buildCompletionMatches(completion, context) {
  if (!completion || !context || typeof completion !== "object" || typeof context !== "object") {
    return false;
  }
  if (!operationContextMatches(
    { requestId: context.requestId, inputPath: context.inputPath },
    { requestId: completion.requestId, inputPath: completion.inputPath },
  )) return false;
  if (!["complete", "failed", "cancelled"].includes(completion.state)
    || typeof completion.message !== "string"
    || completion.message.length === 0
    || completion.message.length > 8192) return false;
  if (completion.state === "complete") {
    return Boolean(completion.output
      && typeof completion.output === "object"
      && typeof completion.output.path === "string"
      && completion.output.path.length > 0
      && completion.output.path.length <= 4096);
  }
  return completion.output == null;
}
