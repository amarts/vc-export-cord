import { mnemonicToMiniSecret } from '@polkadot/util-crypto';
import { getPublicKey, sign, etc } from '@noble/ed25519';
import { encode } from 'multibase';
import { sha512 } from '@noble/hashes/sha512';
import * as secp from '@noble/secp256k1';
import * as jsonld from 'jsonld'; // For canonicalizing JSON-LD data
import { sha256 } from '@noble/hashes/sha256';
import { SignJWT, CompactSign } from 'jose';
//import { encode as base58Encode } from 'base58-universal';
import base58 from 'bs58'

const mnemonic = 'test walk nut penalty hip pave soap entry language right filter choice';

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
    const publicKey = secp.getPublicKey(privateKey, false);
    
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

/*
    // Create the JWS with CompactSign
    const jws = await new CompactSign(new Uint8Array(""))
        .setProtectedHeader(protectedHeader)
        .sign({
            sign: async (data: Uint8Array) => {
                // Use noble-secp256k1 to sign the data
                const signature = await secp.signAsync(data, privateKey);
                return signature;
            },
            key: null, // No need for a KeyObject
        });
   console.log(jws);
*/	
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
    const seed = mnemonicToMiniSecret(mnemonic);
    const privateKey = seed.slice(0, 32); // Use the first 32 bytes for the private key
    const publicKey = secp.getPublicKey(privateKey, true);
    const multicodecPrefixedKey = new Uint8Array([0xe7, 0x01, ...publicKey]);

    const unitArray = new Uint8Array(2 + publicKey.length)
    unitArray[0] = 0xe7
    unitArray[1] = 0x01
    unitArray.set(publicKey, 2)

    const buffer = Buffer.from(unitArray)

    let key =  `z${base58.encode(buffer)}`
    console.log('Key: ', key);
    // Step 3: Base58btc encode the multicodec-prefixed key
    const encodedKey = base58.encode(multicodecPrefixedKey);
    console.log("key: ", encodedKey);
    //const encodedPublicKey = encode('base58btc', multicodecPrefixedKey)
    //let encodedKey = new TextDecoder().decode(encodedPublicKey);
    const verificationMethod = `did:key:z${encodedKey}#z${encodedKey}`;    

    vc.issuanceDate = new Date().toISOString();
    vc.holder = {
	id: 'did:web:oid4vci.demo.cord.network:3zKcL2oAsvZZwFA5uPxtysk5jsai2TGx4AvrpJcBYmAwzGyN'
    };

    vc.id = "testing:1234";
    vc.credentialSubject = { "email": "amar@dhiway.com"};
    // vc.credentialSchema = { ...newSchemaContent }
    //vc.issuer = didDocument.id;
    vc.issuer = `did:key:z${encodedKey}`;
    
    //const signedVC = await signVC(vc, verificationMethod);
    //const signedVC = await signVC1(vc, verificationMethod, privateKey);    
    const signedVC = await signVC2(vc, privateKey, verificationMethod);    
    console.log("SignedVC: ", signedVC, '\n', JSON.stringify(signedVC));
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

