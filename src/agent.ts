import {
  CredentialPayload,
  ICanIssueCredentialTypeArgs,
  ICanVerifyDocumentTypeArgs,
  ICreateVerifiableCredentialArgs,
  ICreateVerifiablePresentationArgs,
  IIdentifier,
  IKey,
  IssuerAgentContext,
  IVerifyCredentialArgs,
  IVerifyPresentationArgs,
  IVerifyResult,
  VerifiableCredential,
  VerifiablePresentation,
  VerifierAgentContext,
} from '@veramo/core-types';

import {
  asArray,
  extractIssuer,
  getChainId,
  intersect,
  isDefined,
  MANDATORY_CREDENTIAL_CONTEXT,
  mapIdentifierKeysToDoc,
  pickSigningKey,
  processEntryToArray,
  removeDIDParameters,
} from '@veramo/utils';

import { AbstractCredentialProvider } from '@veramo/credential-w3c';

import { AddSigningAlgorithm, AddVerifierAlgorithm, decodeJWT } from 'did-jwt';

import {
  ethTypedDataSigner,
  EthTypedDataSignerAlgorithm,
  verifyEthTypedDataSignature,
  validSignatures,
} from 'did-jwt-eth-typed-data-signature';

import {
  createVerifiableCredentialJwt,
  Issuer,
  normalizeCredential,
  verifyCredential as verifyCredentialJWT,
  createVerifiablePresentationJwt,
  verifyPresentation as verifyPresentationJWT,
  normalizePresentation,
  JwtCredentialPayload,
  JwtPresentationPayload,
} from 'did-jwt-vc';

import { EthrDID } from 'ethr-did';
import { Resolvable } from 'did-resolver';
import canonicalize from 'canonicalize';

export class CredentialProviderEip712JWT implements AbstractCredentialProvider {
  constructor() {
    AddSigningAlgorithm('EthTypedDataSignature', EthTypedDataSignerAlgorithm());
    AddVerifierAlgorithm('EthTypedDataSignature', verifyEthTypedDataSignature, validSignatures);
  }

  /** {@inheritdoc @veramo/credential-w3c#AbstractCredentialProvider.matchKeyForType} */
  matchKeyForType(key: IKey): boolean {
    return this.matchKeyForEip712(key);
  }

  /** {@inheritdoc @veramo/credential-w3c#AbstractCredentialProvider.getTypeProofFormat} */
  getTypeProofFormat(): string {
    return 'jwt';
  }

  /** {@inheritdoc @veramo/credential-w3c#AbstractCredentialProvider.canIssueCredentialType} */
  canIssueCredentialType(args: ICanIssueCredentialTypeArgs): boolean {
    return args.proofFormat === 'EthTypedDataSignature';
  }

  matchKeyForEip712(key: IKey): boolean {
    switch (key.type) {
      case 'Secp256k1':
        return intersect(key.meta?.algorithms ?? [], ['ES256K', 'ES256K-R']).length > 0;
      default:
        return false;
    }
  }
  /** {@inheritdoc @veramo/credential-w3c#AbstractCredentialProvider.canVerifyDocumentType */
  canVerifyDocumentType(args: ICanVerifyDocumentTypeArgs): boolean {
    const { document } = args;
    return (
      typeof document === 'string' ||
      ((<VerifiableCredential>document)?.proof?.jwt && (<VerifiableCredential>document)?.domain)
    );
  }

  /** {@inheritdoc @veramo/credential-w3c#AbstractCredentialProvider.createVerifiableCredential} */
  async createVerifiableCredential(
    args: ICreateVerifiableCredentialArgs,
    context: IssuerAgentContext
  ): Promise<VerifiableCredential> {
    const { ...otherOptions } = args;
    const credentialContext = processEntryToArray(args?.credential?.['@context'], MANDATORY_CREDENTIAL_CONTEXT);

    const credentialType = processEntryToArray(args?.credential?.type, 'VerifiableCredential');
    const credential: CredentialPayload = {
      ...args?.credential,
      '@context': credentialContext,
      type: credentialType,
    };

    const issuer = extractIssuer(credential, { removeParameters: true });
    if (!issuer || typeof issuer === 'undefined') {
      throw new Error('invalid_argument: args.credential.issuer must not be empty');
    }

    let identifier: IIdentifier;
    try {
      identifier = await context.agent.didManagerGet({ did: issuer });
    } catch (e) {
      throw new Error(`invalid_argument: args.credential.issuer must be a DID managed by this agent. ${e}`);
    }

    const key = pickSigningKey(identifier);
    let keyRef = args.keyRef;

    identifier = await context.agent.didManagerGet({ did: issuer });

    if (!keyRef) {
      const key = identifier.keys.find(
        (k) => k.type === 'Secp256k1' && k.meta?.algorithms?.includes('eth_signTypedData')
      );
      if (!key) throw Error('key_not_found: No suitable signing key is known for ' + identifier.did);
      keyRef = key.kid;
    }

    let chainId;

    const extendedKeys = await mapIdentifierKeysToDoc(
      identifier,
      'verificationMethod',
      context,
      args.resolutionOptions
    );
    const extendedKey = extendedKeys.find((key) => key.kid === keyRef);
    if (!extendedKey) throw Error('key_not_found: The signing key is not available in the issuer DID document');
    try {
      chainId = getChainId(extendedKey.meta.verificationMethod);
    } catch {
      chainId = 1;
    }
    const domain = {
      chainId,
      name: 'VerifiableCredential',
      version: '1',
    };

    credential.domain = domain;
    const ethersSigner = key.meta?.account;
    const jwtSigner = ethTypedDataSigner(ethersSigner, domain);

    const issuerJwt = new EthrDID({
      chainNameOrId: chainId,
      identifier: identifier.did,
      alg: 'EthTypedDataSignature',
      signer: jwtSigner,
    }) as Issuer;

    const jwt = await createVerifiableCredentialJwt(
      credential as unknown as JwtCredentialPayload,
      issuerJwt,
      otherOptions
    );
    return normalizeCredential(jwt);
  }

  /** {@inheritdoc ICredentialVerifier.verifyCredential} */
  async verifyCredential(args: IVerifyCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult> {
    const { credential, policies, ...otherOptions } = args;
    let verifiedCredential: VerifiableCredential;
    let verificationResult: IVerifyResult | undefined = { verified: false };
    const jwt: string = typeof credential === 'string' ? credential : credential.proof.jwt;
    let message;
    const resolver = {
      resolve: (didUrl: string) =>
        context.agent.resolveDid({
          didUrl,
          options: otherOptions?.resolutionOptions,
        }),
    } as Resolvable;

    try {
      // needs broader credential as well to check equivalence with jwt
      verificationResult = await verifyCredentialJWT(jwt, resolver, {
        ...otherOptions,
        policies: {
          ...policies,
          nbf: policies?.nbf ?? policies?.issuanceDate,
          iat: policies?.iat ?? policies?.issuanceDate,
          exp: policies?.exp ?? policies?.expirationDate,
          aud: policies?.aud ?? policies?.audience,
        },
      });
      verifiedCredential = verificationResult.verifiableCredential;

      // if credential was presented with other fields, make sure those fields match what's in the JWT
      if (typeof credential !== 'string' && credential.proof.type === 'JwtProof2020') {
        const credentialCopy = JSON.parse(JSON.stringify(credential));
        delete credentialCopy.proof.jwt;

        const verifiedCopy = JSON.parse(JSON.stringify(verifiedCredential));
        delete verifiedCopy.proof.jwt;

        if (canonicalize(credentialCopy) !== canonicalize(verifiedCopy)) {
          verificationResult.verified = false;
          verificationResult.error = new Error('invalid_credential: Credential JSON does not match JWT payload');
        }
      }
    } catch (e) {
      message = (e as Error).message;
    }
    if (verificationResult.verified) {
      return verificationResult;
    }
    return {
      verified: false,
      error: {
        message,
      },
    };
  }

  /** {@inheritdoc @veramo/credential-w3c#AbstractCredentialProvider.createVerifiablePresentation} */
  async createVerifiablePresentation(
    args: ICreateVerifiablePresentationArgs,
    context: IssuerAgentContext
  ): Promise<VerifiablePresentation> {
    const { challenge, removeOriginalFields, ...otherOptions } = args;
    let { presentation, now, keyRef } = args;
    const presentationContext: string[] = processEntryToArray(
      args?.presentation?.['@context'],
      MANDATORY_CREDENTIAL_CONTEXT
    );
    const presentationType = processEntryToArray(args?.presentation?.type, 'VerifiablePresentation');
    presentation = {
      ...presentation,
      '@context': presentationContext,
      type: presentationType,
    };

    if (!isDefined(presentation.holder)) {
      throw new Error('invalid_argument: presentation.holder must not be empty');
    }

    if (presentation.verifiableCredential) {
      presentation.verifiableCredential = presentation.verifiableCredential.map((cred) => {
        // map JWT credentials to their canonical form
        if (typeof cred !== 'string' && cred.proof.jwt) {
          return cred.proof.jwt;
        } else {
          return cred;
        }
      });
    }

    const holder = removeDIDParameters(presentation.holder);

    let identifier: IIdentifier;
    try {
      identifier = await context.agent.didManagerGet({ did: holder });
    } catch {
      throw new Error('invalid_argument: presentation.holder must be a DID managed by this agent');
    }
    const key = pickSigningKey(identifier, keyRef);
    // only add issuanceDate for JWT
    now = typeof now === 'number' ? new Date(now * 1000) : now;
    if (!Object.getOwnPropertyNames(presentation).includes('issuanceDate')) {
      presentation.issuanceDate = (now instanceof Date ? now : new Date()).toISOString();
    }

    const alg = 'EthTypedDataSignature';

    identifier = await context.agent.didManagerGet({ did: holder });

    if (!keyRef) {
      const key = identifier.keys.find(
        (k) => k.type === 'Secp256k1' && k.meta?.algorithms?.includes('eth_signTypedData')
      );
      if (!key) throw Error('key_not_found: No suitable signing key is known for ' + identifier.did);
      keyRef = key.kid;
    }

    let chainId;

    const extendedKeys = await mapIdentifierKeysToDoc(
      identifier,
      'verificationMethod',
      context,
      args.resolutionOptions
    );
    const extendedKey = extendedKeys.find((key) => key.kid === keyRef);
    if (!extendedKey) throw Error('key_not_found: The signing key is not available in the issuer DID document');
    try {
      chainId = getChainId(extendedKey.meta.verificationMethod);
    } catch {
      chainId = 1;
    }
    const domain = {
      chainId,
      name: 'VerifiablePresentation',
      version: '1',
    };

    presentation.domain = domain;
    const ethersSigner = key.meta?.account;
    const jwtSigner = ethTypedDataSigner(ethersSigner, domain);

    const jwt = await createVerifiablePresentationJwt(
      presentation as unknown as JwtPresentationPayload,
      { did: identifier.did, signer: jwtSigner, alg },
      { removeOriginalFields, challenge, ...otherOptions }
    );
    //FIXME: flagging this as a potential privacy leak.
    return normalizePresentation(jwt);
  }

  /** {@inheritdoc @veramo/credential-w3c#AbstractCredentialProvider.verifyPresentation} */
  async verifyPresentation(args: IVerifyPresentationArgs, context: VerifierAgentContext): Promise<IVerifyResult> {
    const { presentation, domain, challenge, policies, ...otherOptions } = args;
    let jwt: string;
    if (typeof presentation === 'string') {
      jwt = presentation;
    } else {
      jwt = presentation.proof.jwt;
    }
    const resolver = {
      resolve: (didUrl: string) =>
        context.agent.resolveDid({
          didUrl,
          options: otherOptions?.resolutionOptions,
        }),
    } as Resolvable;

    let audience = domain;
    if (!audience) {
      const { payload } = await decodeJWT(jwt);
      if (payload.aud) {
        // automatically add a managed DID as audience if one is found
        const intendedAudience = asArray(payload.aud);
        const managedDids = await context.agent.didManagerFind();
        const filtered = managedDids.filter((identifier) => intendedAudience.includes(identifier.did));
        if (filtered.length > 0) {
          audience = filtered[0].did;
        }
      }
    }

    let message;
    try {
      const result = await verifyPresentationJWT(jwt, resolver, {
        challenge,
        domain,
        audience,
        policies: {
          ...policies,
          nbf: policies?.nbf ?? policies?.issuanceDate,
          iat: policies?.iat ?? policies?.issuanceDate,
          exp: policies?.exp ?? policies?.expirationDate,
          aud: policies?.aud ?? policies?.audience,
        },
        ...otherOptions,
      });
      if (result) {
        return {
          verified: true,
          verifiablePresentation: result,
        };
      }
    } catch (e) {
      message = (e as Error).message;
    }
    return {
      verified: false,
      error: {
        message,
        errorCode: message?.split(':')[0],
      },
    };
  }
}
