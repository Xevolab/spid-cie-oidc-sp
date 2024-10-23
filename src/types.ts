/*
 * Author    : Francesco
 * Created at: 2024-09-02 17:57
 * Edited by : Francesco
 * Edited at : 2024-10-21 22:48
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

import type { KeyObject } from "crypto";
import { JwtPayload } from "jsonwebtoken";

export type IDP = {
	/** Custom unique ID given to an IDP. Will be passed to the authorize endpoint */
	id: string
	/** The IDP's entity ID, meaning it's full URL */
	entityID: string
	/** Dangerous: disable trust chain validation for this IDP */
	dangerous_disableTrustChainValidation?: boolean
}

/** The trust chain that resulted in validating an IDP, as an array of JWT tokens */
export type TrustChain = string[];

export type TrustMark = {
	/** The unique identifier of the trust mark */
	id: string
	/** The entity ID that issued the trust mark */
	iss: string
	/** The trust mark itself, as a JWT */
	trust_mark: string
}

/**
 * Key in JSON Web Key format
 */
export type JWK = {
	/** Key type */
	kty: string
	/** Key usage, typically `sig` or `enc` */
	use: string
	/** Key ID */
	kid: string
	/** Algorithm */
	alg: string
	/** RSA modulus */
	n: string
	/** RSA public exponent */
	e: string
}

/**
 * Key pair of public and private key in PEM format
 */
export type KeyPair = {
	/** The private key in PEM format */
	private: string
	/** The public key in PEM format */
	public: string
}

/**
 * Entity that contains a key pair for signing and encryption purposes
 */
export type UseKeyPair = {
	/** The key used to sign data */
	sig?: KeyPair
	/** The key used to encrypt data */
	enc?: KeyPair
}

/**
 * Object containing the keys used by the OIDC client for the 2 main purposes:
 * - OIDC: used to sign and encrypt OIDC data
 * - Federation: used to sign federation metadata
 */
export type OIDCKeys = {
	/** The keypair used to sing and encrypt OIDC data */
	oidc: UseKeyPair
	/** The key used to sign federation data (enc can be null) */
	federation: UseKeyPair
}

export type TokenRequestPayload = {
	client_id: string;
	/** A JWT string */
	client_assertion: string;
	client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
	code: string;
	code_verifier: string;
	grant_type: "authorization_code";
}

/** Shared logger payload properties */
interface ILoggerPayload {
	trustChain: TrustChain
	/** URL to which the request was sent */
	endpoint?: string
}
export interface IAuthorizationRequestPayload extends ILoggerPayload {
	/** The JWT sent to the IDP */
	request: string
}
export interface IAuthorizationResponsePayload extends ILoggerPayload {
	/** The authorization token provided by the IDP */
	code: string
}
export interface ITokenRequestPayload extends ILoggerPayload {
	/** The authorization token provided by the IDP */
	request: TokenRequestPayload
}
export interface ITokenResponsePayload extends ILoggerPayload {
	/** Access token provided by the IDP */
	accessToken: string,
	/** ID token provided by the IDP */
	idToken: string
}
export type IUserInfoRequestPayload = ILoggerPayload
export interface IUserInfoResponsePayload extends ILoggerPayload {
	/** User information provided by the IDP */
	userinfo: string
}
export type LoggerFunction = (
	/** The unique identifier for a specific authentication "transaction" */
	state: string,
	/** The event that happened */
	event: "authorizationRequest" | "authorizationResponse"
		| "tokenRequest" | "tokenResponse"
		| "userInfoRequest" | "userInfoResponse",
	/** The content of the event */
	payload: IAuthorizationRequestPayload | IAuthorizationResponsePayload
		| ITokenRequestPayload | ITokenResponsePayload
		| IUserInfoRequestPayload | IUserInfoResponsePayload
) => void

/**
 * Class constructor object
 */
export type ConstructorObject = {
	/** The client ID for the OIDC client */
	clientID: string
	/** The list of OIDC providers */
	providers: IDP[]
	/** The callback URL after the authentication process (defaults to clientID+"/callback") */
	callbackURL?: string
	/** An object containing the keys, grouped by use */
	keys: OIDCKeys
	/** The SPID level to request (1, 2 or 3, default is 2) */
	spidLevel?: (1 | 2 | 3)
	/** The list of attributes to request from the IDP */
	attributes: string[]
	/** The trust anchors for the IDP */
	trustAnchors: string[]
	/** The list of trustmarks provided by the RP */
	trustMarks?: TrustMark[]
	/** The logger function, which will be called on OIDC events */
	logger?: LoggerFunction
}

/**
 * Parsed KeyPair object returned by the parseKeyObject function,z
 */
export type ParsedKeyPair = {
	/** What the key is used for */
	name: string
	/** The use for the key, typically `enc` or `sig` */
	use: string
	/** The key ID */
	kid: string
	/** The algorithm used */
	alg: string
	/** The public key parsed in node crypto type */
	public: KeyObject
	/** The private key parsed in node crypto type */
	private: KeyObject
}

/**
 * Extended version of the IDP object, with the configuration and trust chain
 */
export type ParsedIDP = IDP & {
	ec: JwtPayload,
	trustChain: TrustChain,
	getKey: (kid: string) => KeyObject,
}

export type Session = {
	providerID: string;
	provider: string;
	nonce: string;
	state: string;
	code: string;
}
