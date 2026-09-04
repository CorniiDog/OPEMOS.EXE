// Presentation of EXE host capabilities; no Core compatibility or trust decisions.
export function presentHostEnvironment(environment) {
  const linux = environment.host_os === "linux";
  const experimental = linux && environment.experimental === true;
  const supported = environment.host_os === "macos" || experimental;
  const ready = supported && environment.ready === true;
  return {
    ready,
    title: experimental ? (ready ? "Experimental Linux host ready" : "Experimental Linux host unavailable") : (ready ? "Ready to build" : "Builder unavailable"),
    message: ready
      ? (experimental ? "Experimental appliance testing is enabled. Physical USB writing is unavailable." : "The isolated builder will start automatically when you begin.")
      : String(environment.message || "Host capabilities could not be verified."),
    details: [environment.host_os, environment.host_arch, environment.acceleration, environment.qemu_version].filter(value => typeof value === "string" && value.length).join(" · "),
    status: ready ? (experimental ? "Experimental" : "Available") : "Unavailable",
  };
}
