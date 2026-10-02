import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {Acme,HOSTNAME,PRODUCTION,authorizationChallenge,checkedUrl,dnsValue,publicJwk,signedRequest,thumbprint} from './Prepare-ManualAcme.mjs';
const {privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:3072});
test('JWS signature and protected header are verifiable',()=>{
    const jws=signedRequest(PRODUCTION+'/new-order','nonce',{},privateKey,null);
    assert.equal(crypto.verify('RSA-SHA256',Buffer.from(jws.protected+'.'+jws.payload),crypto.createPublicKey(privateKey),Buffer.from(jws.signature,'base64url')),true);
    const header=JSON.parse(Buffer.from(jws.protected,'base64url'));
    assert.equal(header.alg,'RS256');assert.equal(header.nonce,'nonce');assert.equal(header.jwk.d,undefined);
});
test('POST-as-GET signs an empty payload',()=>assert.equal(signedRequest(PRODUCTION+'/order','n',null,privateKey,PRODUCTION+'/account').payload,''));
test('DNS value has the RFC key authorization digest',()=>{
    const token='0123456789abcdefghijklmnop';const jwk=publicJwk(privateKey);
    assert.equal(dnsValue(token,jwk),crypto.createHash('sha256').update(token+'.'+thumbprint(jwk)).digest('base64url'));
    assert.equal(dnsValue(token,jwk).length,43);
});
test('Cross-origin URLs, HTTP, credentials and fragments are rejected',()=>{
    for(const url of ['http://acme-v02.api.letsencrypt.org/a','https://evil.example/a',PRODUCTION+'/a#fragment','https://user@acme-v02.api.letsencrypt.org/a']) assert.throws(()=>checkedUrl(url,PRODUCTION));
});
test('Invalid token rejected',()=>assert.throws(()=>dnsValue('invalid token',publicJwk(privateKey))));
test('Missing nonce rejected',()=>assert.throws(()=>signedRequest(PRODUCTION+'/a',null,{},privateKey,null)));
test('Only pending DNS-01 for exact hostname allowed',()=>{
    const good={identifier:{type:'dns',value:HOSTNAME},status:'pending',challenges:[{type:'dns-01',status:'pending'}]};
    assert.equal(authorizationChallenge(good).type,'dns-01');
    for(const changed of [{...good,identifier:{type:'dns',value:'other.example'}},{...good,wildcard:true},{...good,status:'invalid'},{...good,challenges:[{type:'http-01',status:'pending'}]}]) assert.throws(()=>authorizationChallenge(changed));
});
test('Transport never follows redirects and retries only badNonce',async()=>{
    const calls=[];let posts=0;
    const mock=async(url,options)=>{
        calls.push(options);assert.equal(options.redirect,'error');
        if(options.method==='HEAD')return new Response(null,{status:200,headers:{'replay-nonce':'nonce-one'}});
        posts++;
        return posts===1?new Response(JSON.stringify({type:'urn:ietf:params:acme:error:badNonce'}),{status:400,headers:{'replay-nonce':'nonce-two'}}):new Response(JSON.stringify({status:'pending'}),{status:201});
    };
    const client=new Acme(PRODUCTION,privateKey,mock);client.directoryInfo={newNonce:PRODUCTION+'/nonce'};
    assert.equal((await client.post(PRODUCTION+'/order',{})).data.status,'pending');assert.equal(posts,2);
});
test('Other errors are not retried or logged verbatim',async()=>{
    let posts=0;
    const mock=async(url,options)=>options.method==='HEAD'?new Response(null,{status:200,headers:{'replay-nonce':'nonce'}}):(posts++,new Response(JSON.stringify({type:'urn:ietf:params:acme:error:rateLimited',detail:'sensitive-detail'}),{status:429}));
    const client=new Acme(PRODUCTION,privateKey,mock);client.directoryInfo={newNonce:PRODUCTION+'/nonce'};
    await assert.rejects(client.post(PRODUCTION+'/order',{}),error=>!error.message.includes('sensitive-detail'));assert.equal(posts,1);
});
