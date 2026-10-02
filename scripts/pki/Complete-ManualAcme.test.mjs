import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {Acme,HOSTNAME,PRODUCTION} from './Prepare-ManualAcme.mjs';
import {inspectPublicChain,validateOrder} from './Complete-ManualAcme.mjs';
const state={origin:PRODUCTION,hostname:HOSTNAME,certificateName:'azzu-web-bff-dev-server-tls',orderUrl:PRODUCTION+'/order',authorizationUrl:PRODUCTION+'/authz',challengeUrl:PRODUCTION+'/chall',finalizeUrl:PRODUCTION+'/finalize'};
const order={status:'ready',identifiers:[{type:'dns',value:HOSTNAME}],authorizations:[state.authorizationUrl],finalize:state.finalizeUrl,expires:new Date(Date.now()+86400000).toISOString()};
test('Exact live order is accepted',()=>validateOrder(order,state));
test('Other hostname, API origin, certificate name or finalize URL rejected',()=>{
    for(const patch of [{hostname:'another.example'},{origin:'https://evil.example'},{certificateName:'azzu-web-bff-dev-oidc'},{finalizeUrl:PRODUCTION+'/different'}]) assert.throws(()=>validateOrder(order,{...state,...patch}));
});
test('Expired, invalid or unknown order rejected',()=>{
    for(const patch of [{expires:'2000-01-01T00:00:00Z'},{status:'invalid'},{status:'unknown'},{authorizations:[]}]) assert.throws(()=>validateOrder({...order,...patch},state));
});
test('Private keys and malformed/unbounded public chains rejected',()=>{
    for(const pem of ['-----BEGIN PRIVATE KEY-----','invalid','x'.repeat(131073)]) assert.throws(()=>inspectPublicChain(pem));
});
test('POST-as-GET certificate download preserves PEM rather than decoding JSON',async()=>{
    const {privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:3072});
    const client=new Acme(PRODUCTION,privateKey,async(url,options)=>options.method==='HEAD'?new Response(null,{status:200,headers:{'replay-nonce':'n'}}):new Response('public-pem-chain',{status:200,headers:{'content-type':'application/pem-certificate-chain'}}));
    client.directoryInfo={newNonce:PRODUCTION+'/nonce'};
    assert.equal(await (await client.postRaw(PRODUCTION+'/cert',null)).text(),'public-pem-chain');
});
