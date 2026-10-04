import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("installation-media controller never regresses an active overall progress value", () => {
  const program = String.raw`
import importlib.util, json, pathlib, types
path = pathlib.Path("builder/welcome/welcome_server.py").resolve()
spec = importlib.util.spec_from_file_location("opemos_welcome_server", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
args = types.SimpleNamespace(
    mock=True,
    ui_root=path.parent,
    runtime=path.parent,
    helper=path.parent / "opemos-install-helper",
    rollback=path.parent / "opemos-rollback-last-update",
    state_root=path.parent,
)
controller = module.Controller(args)
controller.operation.update(status="running", phase="slot-b", progress=82)
controller.update_operation(phase="preparing", progress=18, message="Formatting a later partition.")
active = controller.operation_status()
controller.update_operation(status="complete", phase="complete", progress=100, terminal=True)
print(json.dumps({"active": active, "complete": controller.operation_status()}))
`;
  const result = spawnSync("python3", ["-c", program], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const evidence = JSON.parse(result.stdout);
  assert.equal(evidence.active.progress, 82);
  assert.equal(evidence.active.phase, "preparing", "stage detail may advance independently of the overall meter");
  assert.equal(evidence.complete.progress, 100);
});
