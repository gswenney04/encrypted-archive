'use strict';
const form=document.getElementById('unlock'),field=document.getElementById('password'),status=document.getElementById('status');
const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function openArchive(research=false){
 if(!field.value){field.reportValidity();return;}
 const password=field.value;field.value='';const controls=[...form.querySelectorAll('button')];controls.forEach(b=>b.disabled=true);status.textContent='Decrypting…';
 try{
  const response=await fetch(research?'research/continuation.enc.json':'content.enc.json',{cache:'no-store',credentials:'omit'});if(!response.ok)throw Error('Load');
  const e=await response.json();if(e.version!==1||e.kdf!=='PBKDF2-SHA256'||e.cipher!=='AES-256-GCM'||e.compression!=='gzip'||e.iterations!==600000||e.aad!=='encrypted-archive-v1')throw Error('Format');
  const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(e.salt),iterations:e.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const zipped=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(e.iv),additionalData:new TextEncoder().encode(e.aad),tagLength:128},key,bytes(e.ciphertext));
  const clear=await new Response(new Blob([zipped]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  if(research){const b=JSON.parse(clear);if(b.format!=='encrypted-archive-workspace')throw Error('Format');const u=URL.createObjectURL(new Blob([clear],{type:'application/json'})),a=document.createElement('a');a.href=u;a.download='research-workspace.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);status.textContent='Downloaded. This file is decrypted; keep it private.';}
  else{document.open();document.write(clear);document.close();}
 }catch(error){status.textContent=error.name==='OperationError'?'Unable to unlock. Check the password; damaged content also fails this check.':'Could not open the archive. Check the connection and use a current browser.';}
 finally{controls.forEach(b=>b.disabled=false);}
}
form.addEventListener('submit',e=>{e.preventDefault();openArchive(false)});
document.getElementById('research').addEventListener('click',()=>openArchive(true));
