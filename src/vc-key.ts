//import { suites } from 'jsonld-signatures';
//import { Ed25519KeyPair } from '@transmute/ed25519-key-pair';
//import { driver as keyDriver } from '@digitalbazaar/did-method-key';

import { mnemonicToMiniSecret } from '@polkadot/util-crypto';
import { getPublicKey, sign, etc } from '@noble/ed25519';
import { encode } from 'multibase';
import { sha512 } from '@noble/hashes/sha512';
//import { EcdsaSecp256k1Signature2019 } from 'ecdsa-secp256k1-signature-2019';
import * as secp from '@noble/secp256k1';
import * as jsonld from 'jsonld'; // For canonicalizing JSON-LD data
import { sha256 } from '@noble/hashes/sha256';
import { SignJWT, CompactSign } from 'jose';

// Example mnemonic
const mnemonic = 'test walk nut penalty hip pave soap entry language right filter choice';
//const mnemonic = 'test walk nut penalty hip pave soap entry language left filter choice';

const vcTemplate = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
	"https://schema.affinidi.com/EmailV1-0.jsonld"
    ],
    "type": ["VerifiableCredential", "Email"]
};

// Set the SHA-512 implementation
etc.sha512Sync = (...args) => sha512(...args);

async function privateKeyToJWK(privateKey: Uint8Array) {
    const publicKey = secp.getPublicKey(privateKey, false); // Compressed public key
    return {
        kty: 'EC',
        crv: 'secp256k1',
        d: Buffer.from(privateKey).toString('base64url'), // Private key
        x: Buffer.from(publicKey.slice(1, 33)).toString('base64url'), // X-coordinate
        y: Buffer.from(publicKey.slice(33)).toString('base64url'), // Y-coordinate
    };
}

async function signVC2(vc: any, privateKey: Uint8Array, verificationMethod: string) {
    // Step 1: Canonicalize the VC (JSON-LD normalization)
    const normalizedVc = jsonld.canonize(vc); // Canonicalizes JSON-LD for deterministic hashing
    const dataHash = sha256(new TextEncoder().encode(normalizedVc)); // Create SHA-256 hash
    const protectedHeader = { alg: 'ES256K', b64: true, crit: ['b64'] };


    // Step 2: Sign the hash using the private key
    //const signature = await secp.signAsync(dataHash, privateKey);

    // Step 3: Encode the signature as Base58 (or Base64URL)
    //console.log(signature, typeof signature, signature.toString('base64'));
    //const encodedSignature = secp.utils.bytesToBase64(signature);

    const jwk = await privateKeyToJWK(privateKey);
    console.log(jwk);
    
    const jws1 = await new SignJWT({})
        .setProtectedHeader(protectedHeader)
        .sign(jwk);
   console.log(jws1);

    // Step 4: Construct the proof
    const proof = {
        type: 'EcdsaSecp256k1Signature2019',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: verificationMethod,
        jws: jws1,
    };

    return { ...vc, proof};
}

async function generateDidAndVerificationMethod(mnemonic: string) {
    // Step 1: Generate a deterministic seed from the mnemonic
    const seed = mnemonicToMiniSecret(mnemonic);

    // Step 2: Generate the Ed25519 key pair
    const privateKey = seed.slice(0, 32); // First 32 bytes for the private key
    const publicKey = await getPublicKey(privateKey);

    // Step 3: Encode the public key using Multibase (base58btc)
    //const encodedPublicKey = Buffer.from(publicKey).toString('base58');
    const encodedPublicKey = encode('base58btc', publicKey)
    let t = new TextDecoder().decode(encodedPublicKey);
    console.log(t, encodedPublicKey, typeof encodedPublicKey);
    
    // Step 4: Generate the DID from the encoded public key
    //    const did = `did:key:z${encodedPublicKey}`;
    const did = `did:key:${t}`;

    // Step 5: Create the verification method
    const verificationMethod = {
        id: `${did}#${t}`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: `${t}`,
    };

    return { did, verificationMethod, privateKey };
}


async function signCredential(vc: any, privateKey: Uint8Array) {
    const data = new TextEncoder().encode(JSON.stringify(vc));
    const signature = await sign(data, privateKey);
    return Buffer.from(signature).toString('base64url'); // Encode as JWS-compatible
}

/*
async function generateDidFromMnemonic(mnemonic: string) {
    // Step 1: Generate a seed from the mnemonic
    const seed = mnemonicToMiniSecret(mnemonic);

    // Step 2: Generate the Ed25519 key pair from the seed
    const keyPair = await Ed25519KeyPair.generate({
        seed: Uint8Array.from(seed),
        type: 'Ed25519',
    });

    // Step 3: Use the key pair to generate a `did:key` DID
    const did = await keyDriver().generate({ keyPair });

    return did;
}

async function generateDidKey() {
    const { didDocument, methodFor } = await generateDidFromMnemonic(mnemonic);
    const verificationMethod = methodFor({ purpose: 'assertionMethod' });

    console.log('DID:', didDocument.id);
    console.log('Verification Method:', verificationMethod);

    return { didDocument, verificationMethod };
}

*/
/*
async function signVC(vc: any, verificationMethod: any) {
    const suite = EcdsaSecp256k1Signature2019({
        key: verificationMethod,
        date: vc.issuanceDate,
    });

    const signedVC = await suites.sign(vc, {
        suite,
        purpose: new suites.AssertionProofPurpose(),
        documentLoader: url => {
            if (url.startsWith('https://www.w3.org/2018/credentials/v1')) {
                return {
                    document: {}
                };
            } else if (url.startsWith('https://schema.affinidi.com/EmailV1-0.jsonld')) {
                return {
                    document: {}
                };
            }
        }
    });

    console.log('Signed VC:', JSON.stringify(signedVC, null, 2));
    return signedVC;
}
*/
async function signVC1(vc: any, verificationMethod: any, privateKey: any) {
    const proof = {
        //    type: 'Ed25519Signature2020',
	type: "EcdsaSecp256k1Signature2019",
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: verificationMethod.id,
        jws: await signCredential(vc, privateKey),
    };

    const signedVC = { ...vc, proof };
    console.log('Signed VC:', signedVC);
    return signedVC
}

async function generateVC() {
    let vc = { ...vcTemplate };
    let newSchemaContent = require('../demo/src/schema.json');
    let content = {
            name: 'Alice',
            age: 29,
            id: '123456789987654321',
            country: 'India',
            address: {
                street: 'a',
                pin: 54032,
                location: {
                    state: 'karnataka',
                },
            },
    };
    //   const { didDocument, verificationMethod } = await generateDidKey();
    //const { did, verificationMethod, privateKey } = await generateDidAndVerificationMethod(mnemonic);
    const seed = mnemonicToMiniSecret(mnemonic);
    const privateKey = seed.slice(0, 32); // Use the first 32 bytes for the private key
    const publicKey = secp.getPublicKey(privateKey, true);

    const encodedPublicKey = encode('base58btc', publicKey)
    let t = new TextDecoder().decode(encodedPublicKey);
    const verificationMethod = `did:key:${t}#${t}`;    

    vc.issuanceDate = new Date().toISOString();
    vc.holder = {
	id: 'did:web:oid4vci.demo.cord.network:3zKcL2oAsvZZwFA5uPxtysk5jsai2TGx4AvrpJcBYmAwzGyN'
    };

    vc.id = "testing:1234";
    vc.credentialSubject = { "email": "amar@dhiway.com"};
    // vc.credentialSchema = { ...newSchemaContent }
    //vc.issuer = didDocument.id;
    vc.issuer = `did:key:${t}`;
    
    //const signedVC = await signVC(vc, verificationMethod);
    //const signedVC = await signVC1(vc, verificationMethod, privateKey);    
    const signedVC = await signVC2(vc, privateKey, verificationMethod);    
    console.log("SignedVC: ", signedVC);
}

async function main() {
      await generateVC();
}

main()
    .then(() => console.log('\nBye! 👋 👋 👋 '))
    .finally();

process.on('SIGINT', async () => {
    console.log('\nBye! 👋 👋 👋 \n');
    //Cord.disconnect();
    process.exit(0);
});

