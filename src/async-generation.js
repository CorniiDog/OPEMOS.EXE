export function createLatestRequestGate() {
  let generation = 0;
  return Object.freeze({
    begin() {
      if (generation === Number.MAX_SAFE_INTEGER) {
        throw new Error("async request generation exhausted");
      }
      generation += 1;
      return generation;
    },
    isCurrent(candidate) {
      return Number.isSafeInteger(candidate) && candidate > 0 && candidate === generation;
    },
  });
}
