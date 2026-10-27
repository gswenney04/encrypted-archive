import fs from 'node:fs';
import {webcrypto} from 'node:crypto';
import vm from 'node:vm';
let password='';for await(const chunk of process.stdin)password+=chunk;password=password.replace(/\r?\n$/,'');
const bytes=s=>Uint8Array.from(Buffer.from(s,'base64'));
for(const file of ['docs/content.enc.json','research/continuation.enc.json']){
 const e=JSON.parse(fs.readFileSync(file));
 const material=await webcrypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
 const key=await webcrypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(e.salt),iterations:e.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
 const zipped=await webcrypto.subtle.decrypt({name:'AES-GCM',iv:bytes(e.iv),additionalData:new TextEncoder().encode(e.aad),tagLength:128},key,bytes(e.ciphertext));
 const clear=await new Response(new Blob([zipped]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
 if(file.startsWith('docs/')){const scripts=[...clear.matchAll(/<script>([\s\S]*?)<\/script>/g)];if(scripts.length!==2)throw Error('Wrong script count');for(const [,js]of scripts)new vm.Script(js);}
 else if(JSON.parse(clear).format!=='encrypted-archive-workspace')throw Error('Wrong bundle');
}
console.log('PASS: Web Crypto and DecompressionStream interoperability; decrypted inline JavaScript parses. Browser UI checks still required.');
