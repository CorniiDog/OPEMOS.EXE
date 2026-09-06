import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { initializeWindowsVmRoot } from "../scripts/windows-vm.mjs";
import { generateWindowsUnattend } from "../scripts/windows-unattend.mjs";
import { createWindowsAnswerMedia } from "../scripts/windows-installer-media.mjs";
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),".."), templates=path.join(repo,"templates","windows");
const input={account:"opemostest",password:"local-onetime-A9!",sshPublicKey:`ssh-ed25519 ${Buffer.alloc(32,8).toString("base64")} test`};
async function fixture(){const parent=await mkdtemp(path.join(os.tmpdir(),"opemos-answer-media-")),root=path.join(parent,"windows-vm");await initializeWindowsVmRoot(root);const file=path.join(root,"runtime","provision-input.json");await writeFile(file,JSON.stringify(input),{mode:0o600});await generateWindowsUnattend(root,file,templates);return{parent,root};}
function runner({code=0,bytes=Buffer.from("fake answer ISO") }={}){return(_command,args)=>{const child=new EventEmitter();child.stderr=new EventEmitter();queueMicrotask(async()=>{if(bytes)await writeFile(args[args.indexOf("-o")+1],bytes,{mode:0o600});if(code)child.stderr.emit("data",Buffer.from("bounded failure"));child.emit("close",code)});return child}}
test("answer media builder uses only the reviewed private pair and deterministic graft names",async()=>{const f=await fixture();try{const out=await createWindowsAnswerMedia(f.root,runner());assert.equal(out.status,"created");assert.equal(out.filename,"opemos-windows-answer.iso");assert.equal(out.size,15);assert.match(out.sha256,/^[0-9a-f]{64}$/);await assert.rejects(createWindowsAnswerMedia(f.root,runner()),/EEXIST/)}finally{await rm(f.parent,{recursive:true,force:true})}});
test("answer media builder rejects changed or permissive inputs before launch",async()=>{for(const change of ["mode","shape"]){const f=await fixture();try{const answer=path.join(f.root,"generated","autounattend.xml");if(change==="mode")await chmod(answer,0o644);else await writeFile(answer,"<unattend/>",{mode:0o600});let called=false;await assert.rejects(createWindowsAnswerMedia(f.root,()=>{called=true}),/mode-0600|reviewed generated shape/);assert.equal(called,false)}finally{await rm(f.parent,{recursive:true,force:true})}}});
test("answer media builder removes only failed output",async()=>{const f=await fixture();try{await assert.rejects(createWindowsAnswerMedia(f.root,runner({code:9})),/bounded failure/);await assert.rejects(readFile(path.join(f.root,"generated","opemos-windows-answer.iso")));assert.match(await readFile(path.join(f.root,"generated","provision.ps1"),"utf8"),/OpenSSH/)}finally{await rm(f.parent,{recursive:true,force:true})}});
test("answer file searches attached filesystems for the reviewed provisioning script",async()=>{const template=await readFile(path.join(templates,"autounattend.xml.template"),"utf8");assert.match(template,/Get-PSDrive -PSProvider FileSystem/);assert.match(template,/opemos-provision\.ps1/);assert.match(template,/if\(-not \$p\)\{exit 31\}/);assert.match(template,/&amp; \$p/);assert.doesNotMatch(template,/C:\\OPEMOS\\provision/)});
