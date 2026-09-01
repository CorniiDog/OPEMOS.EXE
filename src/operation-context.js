export function operationContextMatches(expected, current) {
  return Object.keys(expected).every((key) => expected[key] === current[key]);
}
