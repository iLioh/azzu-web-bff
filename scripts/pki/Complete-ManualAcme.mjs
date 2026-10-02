/** Complete ONLY the existing server order; output public certs, never server keys.
 * Azure Key Vault merge is a separate, fingerprint/CSR-gated private Job.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {HOSTNAME,PRODUCTION,checkedUrl,dnsValue,existingSession,publicJwk} from './Prepare-ManualAcme.mjs';
const openssl='C:/Program Files/Git/usr/bin/openssl.exe';
const trustBundle='C:/Program Files/Git/usr/ssl/certs/ca-bundle.crt';
const sha256=data=>crypto.createHash('sha256').update(data).digest('hex').toUpperCase();
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function opensslRun(args){
    const result=spawnSync(openssl,args,{encoding:'utf8',windowsHide:true,timeout:20000});
    if(result.status!==0) throw new Error('OpenSSL verification failed; do not merge');
    return result.stdout;
}
export function validateOrder(order,state){
    if(state.origin!==PRODUCTION || state.hostname!==HOSTNAME || state.certificateName!=='azzu-web-bff-dev-server-tls'
        || order.identifiers?.length!==1 || order.identifiers[0].type!=='dns' || order.identifiers[0].value!==HOSTNAME
        || order.authorizations?.length!==1 || order.authorizations[0]!==state.authorizationUrl
        || order.finalize!==state.finalizeUrl || !['pending','ready','processing','valid'].includes(order.status)) throw new Error('Order identity/status gate failed');
    if(order.status!=='valid' && (!order.expires || Date.parse(order.expires)<=Date.now())) throw new Error('ACME order expired');
    for(const value of [state.orderUrl,state.authorizationUrl,state.finalizeUrl,state.challengeUrl]) checkedUrl(value,PRODUCTION);
}
export function inspectPublicChain(pem){
    if(pem.includes('PRIVATE KEY') || pem.length>131072) throw new Error('Only bounded public certificate PEM accepted');
    const pieces=pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    if(pieces.length<2 || pieces.length>5 || pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,'').trim()) throw new Error('Unexpected public certificate chain');
    const certificates=pieces.map(piece=>new crypto.X509Certificate(piece));
    const leaf=certificates[0];
    if(leaf.ca || leaf.checkHost(HOSTNAME,{subject:'never',wildcards:false})!==HOSTNAME
        || leaf.subjectAltName!=='DNS:'+HOSTNAME && leaf.subjectAltName!=='DNS: '+HOSTNAME
        || !leaf.keyUsage?.includes('1.3.6.1.5.5.7.3.1')
        || leaf.publicKey.asymmetricKeyType!=='rsa' || leaf.publicKey.asymmetricKeyDetails.modulusLength<3072
        || Date.parse(leaf.validFrom)>Date.now() || Date.parse(leaf.validTo)<=Date.now()+7*86400000) throw new Error('Public server leaf security gate failed');
    for(let i=0;i<certificates.length-1;i++){
        if(!certificates[i+1].ca || !certificates[i].verify(certificates[i+1].publicKey)) throw new Error('Public chain signature gate failed');
    }
    return {pieces,certificates,leaf};
}
async function verifyPublicTxt(state){
    for(const resolver of ['https://dns.google/resolve','https://cloudflare-dns.com/dns-query']){
        const result=await fetch(resolver+'?name='+encodeURIComponent(state.txtName)+'&type=TXT',{headers:{Accept:'application/dns-json'},redirect:'error',signal:AbortSignal.timeout(15000)});
        if(!result.ok) throw new Error('DNS resolver HTTP '+result.status);
        const body=await result.json();
        if(body.Status!==0 || body.Answer?.some(row=>row.type===5)
            || !body.Answer?.some(row=>row.type===16 && row.data.replace(/^"|"$/g,'')===state.txtValue)) throw new Error('Expected direct TXT is not visible at both public resolvers');
    }
    console.log('PUBLIC_TXT_EXACT_MATCH_PASS');
}
export async function main(args=process.argv.slice(2)){
    if(args.length!==1 || args[0]!=='--execute-existing-production-order') throw new Error('Explicit existing production order authorization required');
    const {client,dir,root}=existingSession('production');
    const statePath=path.join(dir,'server-order.json');
    let state=JSON.parse(fs.readFileSync(statePath,'utf8'));
    const save=patch=>{state={...state,...patch};fs.writeFileSync(statePath,JSON.stringify(state,null,2));};
    const csrPath=path.resolve(state.csrFile);
    if(!csrPath.startsWith(root+path.sep) || !csrPath.endsWith('.csr.der')) throw new Error('Unexpected existing CSR path');
    const csr=fs.readFileSync(csrPath);
    if(sha256(csr)!==state.csrSha256.toUpperCase()) throw new Error('Existing CSR hash mismatch');
    opensslRun(['req','-in',csrPath,'-inform','DER','-verify','-noout']);
    const csrText=opensslRun(['req','-in',csrPath,'-inform','DER','-noout','-text']);
    if(!csrText.includes('DNS:'+HOSTNAME) || !csrText.includes('Public-Key: (3072 bit)') || !csrText.includes('TLS Web Server Authentication')) throw new Error('Existing CSR security gate failed');
    const csrPublic=opensslRun(['req','-in',csrPath,'-inform','DER','-pubkey','-noout']).trim();
    await client.directory();
    let order=(await client.post(state.orderUrl,null)).data;
    validateOrder(order,state);
    let auth=(await client.post(state.authorizationUrl,null)).data;
    if(auth.identifier?.type!=='dns' || auth.identifier.value!==HOSTNAME || auth.wildcard) throw new Error('Authorization identity mismatch');
    if(auth.status!=='valid'){
        if(auth.status!=='pending') throw new Error('Authorization terminal status '+auth.status);
        const challenge=auth.challenges?.find(row=>row.type==='dns-01' && row.url===state.challengeUrl);
        if(!challenge || !['pending','processing'].includes(challenge.status) || dnsValue(challenge.token,publicJwk(client.key))!==state.txtValue) throw new Error('Existing challenge mismatch');
        await verifyPublicTxt(state);
        if(challenge.status==='pending' && !state.challengeSubmitted){
            save({status:'ACME_CHALLENGE_SUBMITTING',challengeSubmitted:true});
            await client.post(state.challengeUrl,{});
            console.log('ACME_DNS_CHALLENGE_SUBMITTED');
        }
        for(let attempt=0;attempt<30;attempt++){
            auth=(await client.post(state.authorizationUrl,null)).data;
            if(auth.status==='valid') break;
            if(auth.status!=='pending') throw new Error('Authorization failed: '+auth.status);
            await pause(3000);
        }
        if(auth.status!=='valid') throw new Error('Authorization still pending; resume this same order later');
    }
    save({status:'ACME_AUTHORIZATION_VALID'});
    console.log('ACME_DNS_AUTHORIZATION_VALID');
    for(let attempt=0;attempt<20;attempt++){
        order=(await client.post(state.orderUrl,null)).data;
        validateOrder(order,state);
        if(order.status!=='pending') break;
        await pause(2000);
    }
    if(order.status==='ready'){
        if(state.finalizeSubmitted) throw new Error('Finalize already submitted but order remains ready; inspect, do not retry blindly');
        save({status:'ACME_FINALIZE_SUBMITTING',finalizeSubmitted:true});
        order=(await client.post(state.finalizeUrl,{csr:csr.toString('base64url')})).data;
        console.log('ACME_FINALIZE_EXISTING_CSR_SUBMITTED');
    }
    for(let attempt=0;attempt<30;attempt++){
        if(order.status==='valid') break;
        if(order.status!=='processing') throw new Error('Order not processing/valid after finalize: '+order.status);
        await pause(3000);
        order=(await client.post(state.orderUrl,null)).data;
    }
    validateOrder(order,state);
    if(order.status!=='valid') throw new Error('Order still processing; resume existing order later');
    const certificateUrl=checkedUrl(order.certificate,PRODUCTION);
    save({status:'ACME_CERTIFICATE_ISSUED',certificateUrl});
    const certificateResponse=await client.postRaw(certificateUrl,null);
    if(!certificateResponse.headers.get('content-type')?.startsWith('application/pem-certificate-chain')) throw new Error('Certificate response content-type gate failed');
    const pem=await certificateResponse.text();
    const {pieces,certificates,leaf}=inspectPublicChain(pem);
    if(leaf.publicKey.export({format:'pem',type:'spki'}).toString().trim()!==csrPublic) throw new Error('Issued certificate does not match Key Vault CSR public key');
    const outputDir=path.join(root,'.azure','pki','acme-issued-public-production');
    fs.mkdirSync(outputDir,{recursive:true});
    const files={chain:path.join(outputDir,'server-chain.pem'),leaf:path.join(outputDir,'server-leaf.pem'),intermediates:path.join(outputDir,'server-intermediates.pem')};
    for(const [file,content] of [[files.chain,pem],[files.leaf,pieces[0]+'\n'],[files.intermediates,pieces.slice(1).join('\n')+'\n']]){
        if(fs.existsSync(file) && fs.readFileSync(file,'utf8')!==content) throw new Error('Unexpected public artifact already exists; do not overwrite');
        if(!fs.existsSync(file)) fs.writeFileSync(file,content,{flag:'wx'});
    }
    // Complete hostname, purpose and chain trust using the existing system CA bundle.
    opensslRun(['verify','-purpose','sslserver','-verify_hostname',HOSTNAME,'-CAfile',trustBundle,'-untrusted',files.intermediates,files.leaf]);
    const verification={certificateName:state.certificateName,hostname:HOSTNAME,csrSha256:state.csrSha256.toUpperCase(),certificateSha256:sha256(leaf.raw),chainSha256:certificates.map(cert=>sha256(cert.raw)),spkiSha256:sha256(leaf.publicKey.export({format:'der',type:'spki'})),notBefore:new Date(leaf.validFrom).toISOString(),notAfter:new Date(leaf.validTo).toISOString(),issuer:leaf.issuer,publicChainPath:files.chain,systemTrustVerified:true,verifiedAt:new Date().toISOString()};
    fs.writeFileSync(path.join(outputDir,'public-verification.json'),JSON.stringify(verification,null,2));
    save({status:'ACME_ISSUED_PUBLIC_CHAIN_VERIFIED',certificateSha256:verification.certificateSha256,publicChainPath:files.chain});
    console.log('PUBLIC_CHAIN_HOSTNAME_CSR_AND_SYSTEM_TRUST_PASS');
    console.log(JSON.stringify(verification,null,2));
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) main().catch(error=>{console.error('SAFE_FAILURE: '+error.message);process.exitCode=1;});
