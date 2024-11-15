import { mnemonicToMiniSecret } from '@polkadot/util-crypto';
import * as secp from '@noble/secp256k1';
import * as jsonld from 'jsonld'; // For canonicalizing JSON-LD data
import { sha256 } from '@noble/hashes/sha256';
import base58 from 'bs58'
import { Secp256k1Key, Secp256k1Signature } from '@affinidi/tiny-lds-ecdsa-secp256k1-2019';
import * as jsigs from 'jsonld-signatures';

const mnemonic = 'test walk nut penalty hip pave soap entry language right filter choice';

const vcTemplate = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
	"https://schema.affinidi.com/EmailV1-0.jsonld"
    ],
    "type": ["VerifiableCredential"]
};

async function signCredential(vc: any, key: any, verificationMethod: string) {
    /* suite is very important */
    const suite = new Secp256k1Signature({
        key,
	date: new Date().toISOString()
    });

    /* this is used for signing */
    const signedDoc = await jsigs.sign(
	{ ...vc },
	{
	    suite,
	    documentLoader: async (url) => {
		if (url.startsWith('https://')) {
		    /* does this always work? */
		    const response = await fetch(url);
		    const json = await response.json();
		    return {
			contextUrl: null,
			document: json,
			documentUrl: url
  		    };
		}
	    },
            purpose: new jsigs.purposes.AssertionProofPurpose(),
            compactProof: false,
	},
    )
    return signedDoc;
}

async function generateVC() {
    let vc = { ...vcTemplate };

    /* get the issuer-did and signing key */
    const seed = mnemonicToMiniSecret(mnemonic);
    const privateKey = seed.slice(0, 32);
    const publicKey = secp.getPublicKey(privateKey, true);

    /* this is key to get the proper did:key */
    const multicodecPrefixedKey = new Uint8Array([0xe7, 0x01, ...publicKey]);

    // Step 3: Base58btc encode the multicodec-prefixed key
    const encodedKey = base58.encode(multicodecPrefixedKey);
    
    const verificationMethod = `did:key:z${encodedKey}#z${encodedKey}`;
    const did = `did:key:z${encodedKey}`;
    
    const key = new Secp256k1Key({
	id: verificationMethod,
	controller: did,
        type: 'EcdsaSecp256k1VerificationKey2019',
	publicKeyHex: Buffer.from(publicKey).toString('hex'),
    	privateKeyHex: Buffer.from(privateKey).toString('hex')
    });

    vc.issuanceDate = new Date().toISOString();
    vc.holder = {
	id: 'did:web:oid4vci.demo.cord.network:3zKcL2oAsvZZwFA5uPxtysk5jsai2TGx4AvrpJcBYmAwzGyN'
    };

    /* This should be based on the 'hash' of the VC (CORD's identifier), and should get 'anchored' to CORD chain,  */
    vc.id = "testing:1234";

    /* This needs to be based on the 'schema', and content for the schema */
    vc.credentialSubject = { "email": "amar@dhiway.com"};

    /* this should be the 'did:key:' generated earlier, but with mnemonic, so it is always same for same issuer */
    vc.issuer = did;
    
    //    const signedVC = await signVC2(vc, privateKey, verificationMethod);
    const signedVC = await signCredential(vc, key, verificationMethod);
    console.log("SignedVC: ", signedVC, '\n');
    console.log("For Affinidi: \n", JSON.stringify(signedVC, null, 2));
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

