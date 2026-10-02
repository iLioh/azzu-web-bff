/** Narrow ACME DNS-01 order preparation, not a certificate deployment.
 * Server key remains in Key Vault. The separate ACME account key is DPAPI-encrypted
 * for this Windows user in an ACL-restricted, Git-ignored local directory.
 * No plaintext account private key is written to disk or passed on command lines.
 * Does NOT submit DNS validation, finalize an order, merge a cert or modify DNS.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

export const HOSTNAME='web-bff.internal.azzu.tech';
export const PRODUCTION='https://acme-v02.api.letsencrypt.org';
export const STAGING='https://acme-staging-v02.api.letsencrypt.org';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const helper=path.join(root,'scripts/pki/Protect-AcmeAccount.ps1');
export const b64=value=>Buffer.from(value).toString('base64url');

export function publicJwk(key) {
    const jwk=crypto.createPublicKey(key).export({format:'jwk'});
    return {e:jwk.e,kty:'RSA',n:jwk.n};
}
export function thumbprint(jwk) {
    return crypto.createHash('sha256').update(JSON.stringify({e:jwk.e,kty:jwk.kty,n:jwk.n})).digest('base64url');
}
export function dnsValue(token,jwk) {
    if (!/^[A-Za-z0-9_-]{16,256}$/.test(token)) throw new Error('Invalid DNS challenge token');
    return crypto.createHash('sha256').update(token+'.'+thumbprint(jwk)).digest('base64url');
}
export function checkedUrl(url,origin) {
    const parsed=new URL(url);
    if(parsed.origin!==origin || parsed.protocol!=='https:' || parsed.username || parsed.password || parsed.hash) throw new Error('ACME URL origin gate failed');
    return parsed.href;
}
export function signedRequest(url,nonce,payload,key,kid) {
    if(!nonce) throw new Error('Missing ACME nonce');
    const header={alg:'RS256',nonce,url,...(kid ? {kid} : {jwk:publicJwk(key)})};
    const protected64=b64(JSON.stringify(header));
    const payload64=payload===null ? '' : b64(JSON.stringify(payload));
    const signature=crypto.sign('RSA-SHA256',Buffer.from(protected64+'.'+payload64),key).toString('base64url');
    return {protected:protected64,payload:payload64,signature};
}
export class Acme {
    constructor(origin,key,fetcher=fetch){this.origin=origin;this.key=key;this.fetch=fetcher;this.nonce=null;this.kid=null;}
    async raw(url,options={}) {
        const response=await this.fetch(checkedUrl(url,this.origin),{...options,redirect:'error',signal:AbortSignal.timeout(25000)});
        this.nonce=response.headers.get('replay-nonce') || this.nonce;
        return response;
    }
    async directory(){
        const response=await this.raw(this.origin+'/directory');
        if(response.status!==200) throw new Error('ACME directory HTTP '+response.status);
        const directory=await response.json();
        for(const field of ['newNonce','newAccount','newOrder']) checkedUrl(directory[field],this.origin);
        this.directoryInfo=directory;
        return directory;
    }
    async postRaw(url,payload){
        checkedUrl(url,this.origin);
        for(let attempt=0;attempt<2;attempt++){
            if(!this.nonce){
                const nonceResponse=await this.raw(this.directoryInfo.newNonce,{method:'HEAD'});
                if(nonceResponse.status!==200 && nonceResponse.status!==204) throw new Error('ACME nonce HTTP '+nonceResponse.status);
            }
            const body=signedRequest(url,this.nonce,payload,this.key,this.kid);
            this.nonce=null;
            const response=await this.raw(url,{method:'POST',headers:{'Content-Type':'application/jose+json'},body:JSON.stringify(body)});
            if(response.ok) return response;
            const data=await response.json();
            if(data.type==='urn:ietf:params:acme:error:badNonce' && attempt===0) continue;
            // Problem details may contain operator inputs; log only public error type.
            throw new Error('ACME HTTP '+response.status+' '+String(data.type||'request-failed'));
        }
        throw new Error('ACME nonce retry exhausted');
    }
    async post(url,payload){
        const response=await this.postRaw(url,payload);
        return {data:await response.json(),location:response.headers.get('location')};
    }
}
export function authorizationChallenge(auth){
    if(auth.identifier?.type!=='dns' || auth.identifier.value!==HOSTNAME || auth.wildcard || auth.status!=='pending') throw new Error('Unexpected authorization identifier/status: '+String(auth.status));
    const challenges=auth.challenges?.filter(c=>c.type==='dns-01' && c.status==='pending') || [];
    if(challenges.length!==1) throw new Error('Expected exactly one pending DNS-01 challenge');
    return challenges[0];
}
function dpapi(mode,input='') {
    const response=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-File',helper,'-Mode',mode],{input,encoding:'utf8',windowsHide:true,timeout:20000});
    if(response.status!==0) throw new Error('DPAPI helper failed; no sensitive output displayed');
    return response.stdout.trim();
}
function privateDirectory(environment){
    if(process.platform!=='win32') throw new Error('Windows CurrentUser DPAPI required');
    const dir=path.join(root,'.azure','pki','acme-manual-'+environment);
    const sid=dpapi('Sid');
    if(!/^S-1-[0-9-]+$/.test(sid)) throw new Error('Invalid local user SID');
    fs.mkdirSync(dir,{recursive:true});
    if(fs.lstatSync(dir).isSymbolicLink()) throw new Error('Private directory must not be a link');
    const acl=spawnSync('icacls.exe',[dir,'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F','*S-1-5-18:(OI)(CI)F'],{encoding:'utf8',windowsHide:true,timeout:15000});
    if(acl.status!==0) throw new Error('Private directory ACL gate failed');
    return dir;
}
function accountKey(dir){
    const file=path.join(dir,'account-key.pkcs8.dpapi');
    if(fs.existsSync(file)) return crypto.createPrivateKey({key:Buffer.from(dpapi('Unprotect',fs.readFileSync(file,'utf8')),'base64'),format:'der',type:'pkcs8'});
    const {privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:3072});
    const privateDer=privateKey.export({format:'der',type:'pkcs8'});
    const encrypted=dpapi('Protect',privateDer.toString('base64'));
    privateDer.fill(0);
    fs.writeFileSync(file,encrypted,{flag:'wx'});
    // Prove decryptability without exposing plaintext.
    const restored=crypto.createPrivateKey({key:Buffer.from(dpapi('Unprotect',encrypted),'base64'),format:'der',type:'pkcs8'});
    assert.deepEqual(publicJwk(restored),publicJwk(privateKey));
    return privateKey;
}
export function existingSession(environment='production'){
    if(process.platform!=='win32' || !['production','staging'].includes(environment)) throw new Error('Existing Windows session required');
    const dir=path.join(root,'.azure','pki','acme-manual-'+environment);
    for(const file of ['account-key.pkcs8.dpapi','account.json','server-order.json']){
        if(!fs.existsSync(path.join(dir,file)) || fs.lstatSync(path.join(dir,file)).isSymbolicLink()) throw new Error('Missing/unsafe existing ACME state');
    }
    if(fs.lstatSync(dir).isSymbolicLink()) throw new Error('ACME state must not be a link');
    const key=accountKey(dir);
    const meta=JSON.parse(fs.readFileSync(path.join(dir,'account.json'),'utf8'));
    const client=new Acme(environment==='production'?PRODUCTION:STAGING,key);
    if(meta.origin!==client.origin || meta.thumbprint!==thumbprint(publicJwk(key))) throw new Error('Existing account mismatch');
    client.kid=checkedUrl(meta.kid,client.origin);
    return {client,dir,root};
}
export async function main(args=process.argv.slice(2)){
    if(!args.includes('--execute') || !args.includes('--accept-terms')) throw new Error('Explicit --execute and --accept-terms required');
    const environment=args.includes('--production')?'production':args.includes('--staging')?'staging':null;
    if(!environment || (args.includes('--production') && args.includes('--staging'))) throw new Error('Select exactly one environment');
    const csrIndex=args.indexOf('--csr');
    if(csrIndex<0 || !args[csrIndex+1]) throw new Error('Verified public server CSR is required');
    const csrFile=path.resolve(args[csrIndex+1]);
    if(!csrFile.startsWith(root+path.sep) || !csrFile.endsWith('.csr.der')) throw new Error('Unexpected public CSR path');
    const csrHash=crypto.createHash('sha256').update(fs.readFileSync(csrFile)).digest('hex');
    const dir=privateDirectory(environment);
    const key=accountKey(dir);
    const acme=new Acme(environment==='production'?PRODUCTION:STAGING,key);
    const directory=await acme.directory();
    const metaPath=path.join(dir,'account.json');
    if(fs.existsSync(metaPath)){
        const meta=JSON.parse(fs.readFileSync(metaPath,'utf8'));
        if(meta.origin!==acme.origin || meta.thumbprint!==thumbprint(publicJwk(key))) throw new Error('Account metadata mismatch');
        acme.kid=checkedUrl(meta.kid,acme.origin);
    } else {
        const account=await acme.post(directory.newAccount,{termsOfServiceAgreed:true});
        if(account.data.status!=='valid') throw new Error('ACME account not valid');
        acme.kid=checkedUrl(account.location,acme.origin);
        fs.writeFileSync(metaPath,JSON.stringify({origin:acme.origin,kid:acme.kid,thumbprint:thumbprint(publicJwk(key)),terms:directory.meta?.termsOfService},null,2),{flag:'wx'});
    }
    const orderPath=path.join(dir,'server-order.json');
    let state;
    let order;
    if(fs.existsSync(orderPath)){
        state=JSON.parse(fs.readFileSync(orderPath,'utf8'));
        if(state.origin!==acme.origin || state.hostname!==HOSTNAME || state.csrSha256!==csrHash) throw new Error('Existing order/CSR mismatch; no overwrite');
        order=(await acme.post(state.orderUrl,null)).data;
    } else {
        const created=await acme.post(directory.newOrder,{identifiers:[{type:'dns',value:HOSTNAME}]});
        order=created.data;
        state={origin:acme.origin,hostname:HOSTNAME,csrFile,csrSha256:csrHash,certificateName:'azzu-web-bff-dev-server-tls',orderUrl:checkedUrl(created.location,acme.origin),createdAt:new Date().toISOString()};
        // Save immediately: never blindly create another order after an uncertain response.
        fs.writeFileSync(orderPath,JSON.stringify(state,null,2),{flag:'wx'});
    }
    if(order.status!=='pending' || order.identifiers?.length!==1 || order.identifiers[0].type!=='dns' || order.identifiers[0].value!==HOSTNAME || order.authorizations?.length!==1 || !order.expires || Date.parse(order.expires)<=Date.now()) throw new Error('Order not a live pending order for the exact server hostname');
    const authorizationUrl=checkedUrl(order.authorizations[0],acme.origin);
    const auth=(await acme.post(authorizationUrl,null)).data;
    const challenge=authorizationChallenge(auth);
    const txt=dnsValue(challenge.token,publicJwk(key));
    state={...state,expires:order.expires,authorizationUrl,challengeUrl:checkedUrl(challenge.url,acme.origin),finalizeUrl:checkedUrl(order.finalize,acme.origin),txtName:'_acme-challenge.'+HOSTNAME,txtRelativeName:'_acme-challenge.web-bff.internal',txtValue:txt,status:'AWAITING_MANUAL_DNS_ONLY'};
    fs.writeFileSync(orderPath,JSON.stringify(state,null,2));
    console.log(JSON.stringify({environment,hostname:HOSTNAME,recordType:'TXT',name:state.txtRelativeName,fullName:state.txtName,value:txt,ttl:300,orderExpires:state.expires,status:state.status,publicCsrSha256:csrHash},null,2));
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
    main().catch(error=>{console.error('SAFE_FAILURE: '+error.message);process.exitCode=1;});
}
