import * as jose from "jose";
import fs from "node:fs/promises";
import fetch from "node-fetch"; 
import { getConfig } from "./config.js";
import {
  ALGORITHM_RSASSA_PSS,
  createProof,
  publicKeyMatchesCertificate,
  writeFile,
} from "./utils.js";

export async function writeDIDFile() {
  const config = getConfig();

  const certificatePem = await fs.readFile(config.pathCertificate, {
    encoding: "utf8",
  });

  const x509 = await jose.importX509(certificatePem, ALGORITHM_RSASSA_PSS);
  const publicKeyJwk = await jose.exportJWK(x509);
  publicKeyJwk.alg = ALGORITHM_RSASSA_PSS;
  publicKeyJwk.x5u = config.urlX5U;

  // A sanity check to catch upstream errors in the Compliance API calls
  if (!publicKeyMatchesCertificate(publicKeyJwk, certificatePem)) {
    throw new Error("Public key does not match certificate");
  }

  const did = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: config.didWebId,
    verificationMethod: [
      {
        "@context": "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
        id: config.didWebId,
        type: "JsonWebKey2020",
        publicKeyJwk,
      },
    ],
    assertionMethod: [`${config.didWebId}#X509-JWK2020`],
  };

  await writeFile(config.pathDID, did);
}

export async function buildParticipantVC() {
  const config = getConfig();
  const validFrom = new Date().toISOString();
  const validUntil = new Date(Date.now() + (86400 * 1000 * 365)).toISOString();
  //Cuenta un año desde ahora, no cuenta bisiestos
  const doc = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#",
    ],
    type: ["VerifiableCredential"],
    id: config.urlParticipant,
    issuer: config.didWebId,
    validFrom: validFrom,
    validUntil: validUntil,
    credentialSubject: {
      id: config.officialUrlParticipant,
      type: "gx:LegalParticipant",
      "gx:legalName": config.legalName,
      "gx:legalRegistrationNumber": {
        id: config.subjectIdLRN,
      },
      "gx:headquarterAddress": {
        "gx:streetAddress": config.streetAddress,
        "gx:postalCode": config.postalCode,
        "gx:locality": config.locality,
        "gx:countrySubdivisionCode": config.countrySubdivisionCode,
      },
      "gx:legalAddress": {
        "gx:streetAddress": config.streetAddress,
        "gx:postalCode": config.postalCode,
        "gx:locality": config.locality,
        "gx:countrySubdivisionCode": config.countrySubdivisionCode,
      },
      
    },
  };

  const proof = await createProof(doc);
  Object.assign(doc, { proof });

  await writeFile(config.pathParticipant, doc);

  return doc;
}

export async function buildLegalRegistrationNumberVC() {
  const config = getConfig();
  const requestBody = {
    "@context": [
      "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant"
    ],
    type: "gx:legalRegistrationNumber",
    id: config.subjectIdLRN,
    "gx:vatID": config.vatID,
  };

  const apiBase = "https://registrationnumber.notary.lab.gaia-x.eu/v1-staging/registrationNumberVC";
  const vcid = config.urlLRN;     // ← URL pública del VC
  const url = `${apiBase}?vcid=${encodeURIComponent(vcid)}`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Notary API error (${response.status}): ${errorText}`);
  }

  const vc = await response.json();
  await writeFile(config.pathLRN, vc);
  return vc;
}

export async function buildTermsConditionsVC() {
  const config = getConfig();
  const validFrom = new Date().toISOString();
  const validUntil = new Date(Date.now() + (86400 * 1000 * 365)).toISOString();
  const termsAndConditions =
    "The PARTICIPANT signing the Self-Description agrees as follows:\n- " +
    "to update its descriptions about any changes, " +
    "be it technical, organizational, or legal - " +
    "especially but not limited to contractual in regards to " +
    "the indicated attributes present in the descriptions.\n\n" +
    "The keypair used to sign Verifiable Credentials will be revoked " +
    "where Gaia-X Association becomes aware of any inaccurate statements " +
    "in regards to the claims which result in a non-compliance " +
    "with the Trust Framework and policy rules defined " +
    "in the Policy Rules and Labelling Document (PRLD).";

  const doc = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#",
    ],
    type: ["VerifiableCredential"],
    id: config.urlTermsConditions,
    issuer: config.didWebId,
    validFrom: validFrom,
    validUntil: validUntil,
    credentialSubject: {
      "@context":
        "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#",
      type: "gx:GaiaXTermsAndConditions",
      id: config.subjectIdTermsConditions,
      "gx:termsAndConditions": termsAndConditions,
    },
  };

  const proof = await createProof(doc);
  Object.assign(doc, { proof });

  await writeFile(config.pathTermsConditions, doc);

  return doc;
}
