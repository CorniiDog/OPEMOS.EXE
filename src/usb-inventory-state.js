export function usbInventoryNeedsRefresh(outputPath, refreshedOutputPath, targetCount) {
  if (typeof outputPath !== "string" || outputPath.length === 0) {
    throw new TypeError("outputPath must be a non-empty string");
  }
  if (refreshedOutputPath !== null && typeof refreshedOutputPath !== "string") {
    throw new TypeError("refreshedOutputPath must be a string or null");
  }
  if (!Number.isSafeInteger(targetCount) || targetCount < 0) {
    throw new TypeError("targetCount must be a non-negative safe integer");
  }
  return refreshedOutputPath !== outputPath || targetCount === 0;
}

export function acceptedUsbInventoryPath(outputPath, outcome) {
  if (typeof outputPath !== "string" || outputPath.length === 0) {
    throw new TypeError("outputPath must be a non-empty string");
  }
  if (!outcome || typeof outcome !== "object" || Array.isArray(outcome)) {
    throw new TypeError("USB inventory outcome must be an object");
  }
  if (typeof outcome.completed !== "boolean") {
    throw new TypeError("USB inventory completed must be boolean");
  }
  if (!Number.isSafeInteger(outcome.targetCount) || outcome.targetCount < 0) {
    throw new TypeError("USB inventory targetCount must be a non-negative safe integer");
  }
  return outcome.completed && outcome.targetCount > 0 ? outputPath : null;
}
