import { mnemonicToMiniSecret } from '@polkadot/util-crypto';
import * as secp from '@noble/secp256k1';
import * as jsonld from 'jsonld'; // For canonicalizing JSON-LD data
import { sha256 } from '@noble/hashes/sha256';
import base58 from 'bs58'
import { Secp256k1Key, Secp256k1Signature } from '@affinidi/tiny-lds-ecdsa-secp256k1-2019';
import * as jsigs from 'jsonld-signatures';
import {v4 as uuidv4} from 'uuid';

const mnemonic = 'test walk nut penalty hip pave soap entry language right filter choice';

const vcTemplate = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
	{
        "credentialSchema": {
          "@id": "https://www.w3.org/2018/credentials#credentialSchema",
          "@type": "@id"
        },
        "email": {
          "@id": "schema-id:email",
      	  "@type": "https://schema.org/Text"
	  },
	"studentName": {
          "@id": "schema-id:studentName",
      	  "@type": "https://schema.org/Text"
        },
	"courseName":  {
          "@id": "schema-id:courseName",
      	  "@type": "https://schema.org/Text"
        },
	"instituteName":  {
          "@id": "schema-id:instituteName",
      	  "@type": "https://schema.org/Text"
        },
	"instituteLogo":  {
          "@id": "schema-id:instituteLogo",
      	  "@type": "https://schema.org/Text"
        },
	"dateOfCompletion":  {
          "@id": "schema-id:dateOfCompletion",
      	  "@type": "https://schema.org/Text"
        },
	"scoreAchieved":  {
          "@id": "schema-id:score",
      	  "@type": "https://schema.org/Text"
        }
      }
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

async function generateVC(content: any, holderDid: string) {
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
	id: holderDid
    };

    /* This should be based on the 'hash' of the VC (CORD's identifier), and should get 'anchored' to CORD chain,  */
    /* TODO: this is where the actual content should be passed */
    vc.id = 'cord:' + uuidv4();

    /* This needs to be based on the 'schema', and content for the schema */
    vc.credentialSubject = {
        id: holderDid,
   	email: content.email,
	studentName: content.studentName,
	courseName: content.courseName,
	instituteName: content.instituteName,
	instituteLogo: content.instituteLogo,
	dateOfCompletion: content.dateOfCompletion,
	scoreAchieved: content.scoreAchieved
    };

    /* this should be the 'did:key:' generated earlier, but with mnemonic, so it is always same for same issuer */
    vc.issuer = did;
    
    //    const signedVC = await signVC2(vc, privateKey, verificationMethod);
    const signedVC = await signCredential(vc, key, verificationMethod);
    console.log("SignedVC: ", signedVC, '\n');
    console.log("For Affinidi: \n", JSON.stringify(signedVC, null, 2));
}

async function main() {
    const content = {
   	email: 'amar@dhiway.com',
	studentName: 'Amar Tumballi',
	courseName: 'Masters in Data Analytics (Dhiway) ',
	instituteName: 'Hogwarts University',
	instituteLogo: '', /* TODO: send URL */
	dateOfCompletion: new Date().toISOString(), /* TODO: make this a old date */
	scoreAchieved: '450/500'
    };
    const holderDid = 'did:web:oid4vci.demo.cord.network:3zKcL2oAsvZZwFA5uPxtysk5jsai2TGx4AvrpJcBYmAwzGyN';
    await generateVC(content, holderDid);
}

main()
    .then(() => console.log('\nBye! 👋 👋 👋 '))
    .finally();

process.on('SIGINT', async () => {
    console.log('\nBye! 👋 👋 👋 \n');
    //Cord.disconnect();
    process.exit(0);
});

