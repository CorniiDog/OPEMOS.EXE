#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, lstat, open, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectWindowsVmRoot } from "./windows-vm.mjs";
function fail(message) { throw new Error(message); }
async function privateFile(file, label, max) { const i=await lstat(file,{bigint:true}); if(i.isSymbolicLink()||!i.isFile()||i.uid!==BigInt(process.getuid())||Number(i.mode&0o777n)!==0o600||i.size<1n||i.size>BigInt(max)) fail(`${label} must be a bounded current-user-owned mode-0600 regular file.`); return i; }
async function hash(file) { const h=createHash("sha256"); await new Promise((ok,no)=>createReadStream(file).on("data",c=>h.update(c)).on("error",no).on("end",ok)); return h.digest("hex"); }
export async function createWindowsAnswerMedia(root, runner = spawn, setMode = chmod) {
  await inspectWindowsVmRoot(root);
  const generated=path.join(root,"generated"), answer=path.join(generated,"autounattend.xml"), provision=path.join(generated,"provision.ps1"), output=path.join(generated,"opemos-windows-answer.iso");
  await privateFile(answer,"Windows answer file",256*1024); await privateFile(provision,"Windows provisioning script",256*1024);
  const xml=await readFile(answer,"utf8"), ps=await readFile(provision,"utf8"), provisionSha256=await hash(provision);
  const digestGuard=`if($h -cne &apos;${provisionSha256}&apos;){exit 34}`;
  if(!xml.includes("<LogonCount>1</LogonCount>")||!xml.includes("FileSystemLabel -ceq &apos;OPEMOS_ANSWER&apos;")||!xml.includes("$v.Count -ne 1")||!xml.includes("Get-FileHash -LiteralPath $p -Algorithm SHA256")||(xml.split(digestGuard).length-1)!==1||xml.includes("Select-Object -First")||xml.includes("Get-PSDrive")||xml.includes("__")) fail("Windows answer file is not bound to the reviewed provisioning script and OPEMOS_ANSWER media.");
  if(!ps.includes("OpenSSH.Server~~~~0.0.1.0")||!ps.includes("PasswordAuthentication no")||ps.includes("__")) fail("Windows provisioning script is not the reviewed generated shape.");
  try { const h=await open(output,"wx",0o600); await h.close(); } catch(e) { throw e; }
  await rm(output);
  const args=["-quiet","-J","-R","-V","OPEMOS_ANSWER","-o",output,"-graft-points",`autounattend.xml=${answer}`,`opemos-provision.ps1=${provision}`];
  try { await new Promise((resolve,reject)=>{const child=runner("genisoimage",args,{stdio:["ignore","ignore","pipe"]}); let error=""; child.stderr?.on("data",c=>{if(error.length<4096)error+=c}); child.on("error",reject); child.on("close",c=>c===0?resolve(c):reject(new Error(`genisoimage failed (${c}): ${error.slice(0,4096)}`)));}); }
  catch (error) { await rm(output,{force:true}); throw error; }
  try { await setMode(output,0o600); } catch(e) { await rm(output,{force:true}); throw e; }
  try { await privateFile(output,"Windows answer media",4*1024*1024); } catch(e) { await rm(output,{force:true}); throw e; }
  return {schemaVersion:1,status:"created",filename:path.basename(output),size:Number((await lstat(output,{bigint:true})).size),sha256:await hash(output),inputs:{answerSha256:await hash(answer),provisionSha256}};
}
function root(){return path.join(path.resolve(path.dirname(fileURLToPath(import.meta.url)),".."),"local-inputs","windows-vm")}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{if(process.argv.length!==3||process.argv[2]!=="create")fail("Usage: scripts/windows-installer-media.mjs create");process.stdout.write(JSON.stringify(await createWindowsAnswerMedia(root()),null,2)+"\n")}catch(e){process.stderr.write(String(e?.message||e)+"\n");process.exitCode=1}}
