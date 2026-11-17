// Dependency-free Node.js 20+ encryption and restore tool. No network calls.
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes,pbkdf2Sync,createCipheriv,createDecipheriv,createHash} from 'node:crypto';
import {gzipSync,gunzipSync} from 'node:zlib';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const aad=Buffer.from('encrypted-archive-v1');
function encrypt(data,password){
 const salt=randomBytes(32),iv=randomBytes(12),iterations=600000;
 const key=pbkdf2Sync(password,salt,iterations,32,'sha256');
 const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(aad);
 const ciphertext=Buffer.concat([cipher.update(gzipSync(data)),cipher.final(),cipher.getAuthTag()]);key.fill(0);
 return {version:1,kdf:'PBKDF2-SHA256',iterations,cipher:'AES-256-GCM',compression:'gzip',aad:aad.toString(),salt:salt.toString('base64'),iv:iv.toString('base64'),ciphertext:ciphertext.toString('base64')};
}
function decrypt(e,password){
 if(e.version!==1||e.kdf!=='PBKDF2-SHA256'||e.cipher!=='AES-256-GCM'||e.compression!=='gzip'||e.aad!==aad.toString()||e.iterations!==600000)throw Error('Unsupported envelope');
 const key=pbkdf2Sync(password,Buffer.from(e.salt,'base64'),e.iterations,32,'sha256');
 const c=Buffer.from(e.ciphertext,'base64'),d=createDecipheriv('aes-256-gcm',key,Buffer.from(e.iv,'base64'));d.setAAD(aad);d.setAuthTag(c.subarray(-16));
 const out=Buffer.concat([d.update(c.subarray(0,-16)),d.final()]);key.fill(0);return gunzipSync(out);
}
function walk(dir,base=dir){return fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(dir,e.name),base):[{path:path.relative(base,path.join(dir,e.name)).replaceAll('\\','/'),encoding:'base64',content:fs.readFileSync(path.join(dir,e.name)).toString('base64')}]);}
function password(){return new Promise((resolve,reject)=>{let s='';process.stdin.setEncoding('utf8');process.stdin.on('data',x=>s+=x);process.stdin.on('end',()=>resolve(s.replace(/\r?\n$/,'')));process.stdin.on('error',reject);});}
const mode=process.argv[2];
if(!['build','restore','test'].includes(mode)){console.error('Usage: supply password via stdin; node tools/archive.mjs build|test|restore [output-directory]');process.exit(1);}
const secret=await password();if(!secret)throw Error('Empty password rejected');
const priv=path.join(root,'private');
if(mode==='build'){
 const dist=path.join(priv,'dist'),read=n=>fs.readFileSync(path.join(dist,n),'utf8'),has=n=>/^[\w.-]+$/.test(n)&&fs.existsSync(path.join(dist,n));
 const inlineJs=t=>t.replace(/<\/script/gi,'<\\/script'),json=v=>JSON.stringify(v).replaceAll('<','\\u003c');
 let html=read('index.html');
 html=html.replace(/<link rel="stylesheet" href="([^"]+)">/g,(m,f)=>has(f)?`<style>${read(f)}</style>`:m);
 // Photos: encrypted one by one into docs/m/ with a key that exists only inside the encrypted page.
 const mdir=path.join(priv,'media'),out=path.join(root,'docs/m'),items=[];let mkey=null;
 if(fs.existsSync(path.join(mdir,'manifest.json'))){
  mkey=JSON.parse(fs.readFileSync(path.join(mdir,'key.json'),'utf8')).b;const K=Buffer.from(mkey,'base64');
  const sealFile=(src,dst)=>{const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',K,iv);fs.writeFileSync(dst,Buffer.concat([iv,c.update(fs.readFileSync(src)),c.final(),c.getAuthTag()]));};
  fs.mkdirSync(out,{recursive:true});const keep=new Set();
  for(const m of JSON.parse(fs.readFileSync(path.join(mdir,'manifest.json'),'utf8')).items){
   if(!m.display||!m.person)continue;const fid=createHash('sha256').update(mkey+m.key).digest('hex').slice(0,20);keep.add(fid+'.bin');keep.add(fid+'.t.bin');
   if(!fs.existsSync(path.join(out,fid+'.bin'))){sealFile(path.join(mdir,'img',m.key+'.jpg'),path.join(out,fid+'.bin'));sealFile(path.join(mdir,'thumb',m.key+'.jpg'),path.join(out,fid+'.t.bin'));}
   const {key,display,hidden_reason,...rec}=m;items.push({...rec,enc:'m/'+fid+'.bin',thumb:'m/'+fid+'.t.bin',k:'b'});}
  for(const f of fs.readdirSync(out))if(!keep.has(f))fs.rmSync(path.join(out,f));
 }
 const pidsFile=path.join(mdir,'pids.json'),pids=fs.existsSync(pidsFile)?JSON.parse(fs.readFileSync(pidsFile,'utf8')):{};
 const docs={};for(const f of ['research-dossier.md','maintenance.md'])if(has(f))docs[f]=read(f);
 html=html.replace('<script src="archive-data.js"></script>',()=>`<script>window.ARCHIVE=${read('archive.json').replaceAll('<','\\u003c')};window.ARCHIVE_DOCS=${json(docs)};window.ARCHIVE_MEDIA=${json({key:mkey,items,pids})};</script>`);
 html=html.replace(/<script src="([^"]+)"><\/script>/g,(m,f)=>has(f)?`<script>${inlineJs(read(f))}</script>`:m);
 if(/<script src=|<link rel="stylesheet"/.test(html))throw Error('Unresolved page dependency');
 const site=encrypt(Buffer.from(html),secret);
 const bundle={format:'encrypted-archive-workspace',version:1,files:walk(priv)};
 const handoff=encrypt(Buffer.from(JSON.stringify(bundle)),secret);
 fs.writeFileSync(path.join(root,'docs/content.enc.json'),JSON.stringify(site));
 fs.writeFileSync(path.join(root,'research/continuation.enc.json'),JSON.stringify(handoff));
 fs.mkdirSync(path.join(root,'docs/research'),{recursive:true});fs.writeFileSync(path.join(root,'docs/research/continuation.enc.json'),JSON.stringify(handoff));
 if(decrypt(site,secret).toString()!==html||decrypt(handoff,secret).toString()!==JSON.stringify(bundle))throw Error('Roundtrip failed');
 console.log('Built two independently salted encrypted bundles; roundtrip passed.');
}else if(mode==='restore'){
 const dest=path.resolve(process.argv[3]||priv);if(fs.existsSync(dest))throw Error('Output already exists; choose a new directory to avoid overwriting research');
 const b=JSON.parse(decrypt(JSON.parse(fs.readFileSync(path.join(root,'research/continuation.enc.json'))),secret));
 if(b.format!=='encrypted-archive-workspace'||b.version!==1)throw Error('Wrong bundle');
 for(const f of b.files){if(!f.path||path.isAbsolute(f.path)||f.path.split('/').some(x=>x==='..'||x==='.')||f.encoding!=='base64')throw Error('Unsafe path');const p=path.resolve(dest,f.path);if(!p.startsWith(dest+path.sep))throw Error('Unsafe path');fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,Buffer.from(f.content,'base64'));}
 console.log('Restored protected workspace. Keep it outside version control.');
}else{
 for(const p of ['docs/content.enc.json','research/continuation.enc.json']){
  const e=JSON.parse(fs.readFileSync(path.join(root,p)));decrypt(e,secret);
  for(const [label,en,pw] of [['wrong password',e,secret+'incorrect'],['tampered ciphertext',{...e,ciphertext:Buffer.from(e.ciphertext,'base64').map((b,i)=>i===20?b^1:b).toString('base64')},secret]]){
   let rejected=false;try{decrypt(en,pw)}catch{rejected=true}if(!rejected)throw Error(label+' accepted');
  }
 }
 const html=decrypt(JSON.parse(fs.readFileSync(path.join(root,'docs/content.enc.json'))),secret).toString();
 if(/<script src=|<link rel="stylesheet"|fetch\('archive.json'\)/.test(html))throw Error('Plaintext dependency remains');
 console.log('PASS: decryption, wrong-password rejection, tamper rejection, self-contained content.');
}
