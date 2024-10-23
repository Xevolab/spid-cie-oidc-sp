/*
 * Author    : Francesco
 * Created at: 2024-03-23 20:56
 * Edited by : Francesco
 * Edited at : 2024-10-22 21:40
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

/* eslint-disable camelcase */
/* eslint-disable no-await-in-loop */

import crypto from "crypto";
import jwt, { JwtPayload } from "jsonwebtoken";
import * as jose from "jose";
import NodeCache from "node-cache";

import axios from "axios";

import { devTrustAnchors } from "./trustAnchors";
import { parseKeyObject } from "./utils";
import { getEntityConfiguration, getEntityConfigurationFromAnchor } from "./oidcUtils";

import {
	ConstructorObject, ParsedKeyPair, JWK, ParsedIDP, Session,
	TokenRequestPayload,
} from "./types";

/**
 * @class OIDCClient
 */
export default class OIDCClient {
	// Creating the sessions cache with a TTL of 3 minutes
	// Here we will save the various login sessions that we are still waiting to get back
	private sessions: NodeCache = new NodeCache({ stdTTL: 60 * 3, checkperiod: 60 * 3 * 2 });

	/** The client ID for the OIDC client */
	readonly clientID: ConstructorObject["clientID"];

	/** The callback URL after the authentication process (defaults to clientID+"/callback") */
	readonly callbackURL: ConstructorObject["callbackURL"];

	/** The SPID level to request (1, 2 or 3, default is 2) */
	readonly spidLevel: ConstructorObject["spidLevel"];

	/** The list of attributes to request from the IDP */
	readonly attributes: ConstructorObject["attributes"];

	private originalTrustAnchors: ConstructorObject["trustAnchors"];

	// Creating a cache also for the trust anchors' EC. The TTL will be based on the exp value
	private trustAnchors: NodeCache = new NodeCache({
		stdTTL: 60 * 60 * 24,
		checkperiod: 60 * 60 * 12,
	});

	/** The list of trustmarks provided by the RP */
	readonly trustMarks: ConstructorObject["trustMarks"];

	private originalProviders: ConstructorObject["providers"];

	// Creating a cache for the providers, where the trust chain will be saved for its TTL
	private providers: NodeCache = new NodeCache({ stdTTL: 60 * 60 * 24, checkperiod: 60 * 60 * 12 });

	private keys: Record<string, { sig: ParsedKeyPair, enc?: ParsedKeyPair }>;

	private logger: ConstructorObject["logger"];

	/**
	 * The constructor for the OIDC client
	 *
	 * @param  options The configuration object for the OIDC client
	 */
	constructor(options: ConstructorObject) {
		const {
			clientID,
			providers = [],
			callbackURL,
			keys,

			spidLevel = 2,
			attributes = ["given_name", "family_name", "https://attributes.eid.gov.it/fiscal_number"],
			trustAnchors = devTrustAnchors,
			trustMarks = [],

			// eslint-disable-next-line @typescript-eslint/no-empty-function
			logger = () => { },
		} = options;

		//

		// Saving config
		this.clientID = clientID;
		this.callbackURL = callbackURL || `${clientID}${clientID.endsWith("/") ? "" : "/"}callback`;
		this.spidLevel = spidLevel;
		this.attributes = attributes;

		// Save the original trust anchors
		this.originalTrustAnchors = trustAnchors;
		// Initiate the process with which the trust anchor configurations will be fetched
		trustAnchors.map(t => this.getTrustAnchor(t));

		// Trust marks
		this.trustMarks = trustMarks;

		// Save the providers and create a cache for their configurations
		this.originalProviders = [...providers];

		// Validating and copying the keys
		if (!keys.oidc) throw new Error("Missing OIDC keys");
		if (!keys.federation) console.warn("[oidc-ts] Federation specific keys are missing. Defaulting to OIDC keys, although this is not recommended: https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/seccons_bcps.html#specializzare-le-chiavi-pubbliche-openid-core-e-federation");
		if (!keys.oidc.sig || !keys.oidc.sig.public || !keys.oidc.sig.private) throw new Error("Missing OIDC signature keys");
		if (!keys.oidc.enc || !keys.oidc.enc.public || !keys.oidc.enc.private) throw new Error("Missing OIDC encryption keys");
		this.keys = {
			oidc: parseKeyObject(keys.oidc, "oidc"),
			federation: parseKeyObject(keys.federation || keys.oidc, "federation"),
		};

		// Warn the user if the logger function is not provided
		if (!logger) console.warn("[oidc-ts] No logger function provided. According to the guidelines, it is required: https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/log_management.html#gestione-dei-log-di-un-op-e-di-un-rp");
		this.logger = logger;
	}

	/**
	 * Get the JWKs for the OIDC client
	 *
	 * @param name The use for getting the keys, which can be "oidc", "federation" or "*"
	 * @return The array of JWKs
	 */
	private getKeys(name: "oidc" | "federation" | "*" = "oidc"): JWK[] {
		if (!["oidc", "federation", "*"].includes(name)) throw new Error("Invalid reason");

		// eslint-disable-next-line no-nested-ternary
		return (
			name === "*"
				? [...Object.values(this.keys.oidc), ...Object.values(this.keys.federation)]
				: Object.values(
					name === "oidc" ? this.keys.oidc : this.keys.federation,
				)
		).map((key: ParsedKeyPair): JWK | undefined => {
			if (!key) return;
			if (!key.public || !key.private) return;
			return {
				alg: key.alg,
				kty: key.private.asymmetricKeyType?.toUpperCase() || "RSA",
				use: key.use, // Assuming it's used for signatures
				// @ts-expect-error n is not in the types but it's a valid property
				n: key.public.n, // Modulus
				// @ts-expect-error e is not in the types but it's a valid property
				e: key.public.e, // Exponent
				kid: key.kid,
			};
		}).filter(Boolean) as JWK[];
	}

	// ---- OIDC Login Endpoints ---- //
	// Reference (in italian): https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/flusso_autenticazione.html

	/**
	 * Get the login URL for the given IDP, to which the user will be redirected to, in order to
	 * start the authentication process
	 *
	 * @param   idp  The IDP ID for which to get the login URL
	 * @return	The response object
	 */
	async authorization(idp: string): Promise<{
		ok: boolean,
		error?: string,
		url?: string,
	}> {
		if (!this.originalProviders.some(e => e.id === idp)) return { ok: false, error: "notFound" };

		let provider: ParsedIDP | null = null;
		try {
			provider = await this.getProvider(idp);
		}
		catch (e) {
			console.error(e);
			return { ok: false, error: "oidcErr" };
		}

		// Initialize the session with all the necessary data
		const session: Session = {
			providerID: provider.id,
			provider: provider.ec.iss,
			nonce: crypto.randomBytes(16).toString("hex"),
			state: crypto.randomBytes(16).toString("hex"),
			code: crypto.randomBytes(16).toString("hex"),
		};

		// Now we need to generate a JWT for the provider
		const jwtToken = jwt.sign({
			iss: this.clientID,
			aud: [
				provider.ec.iss,
				provider.ec.metadata.openid_provider.authorization_endpoint,
			],

			client_id: this.clientID,
			response_type: "code",
			scope: "openid",
			prompt: "consent login",
			redirect_uri: this.callbackURL,

			code_challenge_method: "S256",
			code_challenge: crypto.createHash("sha256").update(session.code).digest("base64url"),

			nonce: session.nonce,
			state: session.state,

			acr_values: new Array(this.spidLevel).fill("")
				.map((_, i) => `https://www.spid.gov.it/SpidL${i + 1}`)
				.reverse()
				.join(" "),
			claims: {
				userinfo: this.attributes.reduce((a, c) => ({ ...a, [c]: null }), {}),
			},
		}, this.keys.oidc.sig.private, {
			algorithm: "RS256",
			expiresIn: "3m",
			keyid: this.keys.oidc.sig.kid,
		});

		// Store the session in the cache
		this.sessions.set(session.state, session);

		// Logging the event
		this.logger(session.state, "authorizationRequest", {
			trustChain: provider.trustChain,
			endpoint: provider.ec.metadata.openid_provider.authorization_endpoint,
			request: jwtToken as string,
		});

		// Redirect the user to the IDP
		return {
			ok: true,
			// eslint-disable-next-line prefer-template
			url: provider.ec.metadata.openid_provider.authorization_endpoint + "?" + new URLSearchParams({
				client_id: this.clientID,
				response_type: "code",
				scope: "openid",
				code_challenge_method: "S256",
				code_challenge: crypto.createHash("sha256").update(session.code).digest("base64url"),
				request: jwtToken,
			}),
		};
	}

	/**
	 * Handle a callback from the IDP after the authentication process has been completed
	 *
	 * @param code   The authorization code returned by the IDP
	 * @param state  The state parameter used for the OIDC flow
	 * @param iss    The issuer of the ID token
	 *
	 * @return  {Promise<CallbackResponse>} The requested user information
	 */
	async callback({ state, code, iss }: {
		state: string,
		code: string,
		iss: string,
	}): Promise<{
		ok: boolean,
		error?: string,
		payload?: Record<string, string>,
	}> {
		// State allows us to retrive the flow session
		const session: Session = this.sessions.get(state);
		if (!session) return { ok: false, error: "oidcExp" };

		// Delete the session upon retrieval
		this.sessions.del(state);

		// Check that the issuer is the same as the one in the session
		if (session.provider !== iss) return { ok: false, error: "oidcInvTok" };

		let provider = null;
		try {
			provider = await this.getProvider(session.providerID);
		}
		catch (e) {
			console.error(e);
			return { ok: false, error: "oidcInvTok" };
		}

		// Logging the response
		this.logger(session.state, "authorizationResponse", {
			trustChain: provider.trustChain,
			code,
		});

		// -> Exchange the authorization code for the user's information

		const requestObject: TokenRequestPayload = {
			client_id: this.clientID,
			client_assertion: jwt.sign({
				iss: this.clientID,
				sub: this.clientID,
				aud: [session.provider, provider.config.metadata.openid_provider.token_endpoint],
				jti: crypto.randomBytes(16).toString("hex"),
			}, this.keys.oidc.sig.private, {
				algorithm: "RS256",
				expiresIn: "3m",
				keyid: this.keys.oidc.sig.kid,
			}),
			client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			code,
			code_verifier: session.code,
			grant_type: "authorization_code",
		};

		// Logging the request to the token endpoint
		this.logger(session.state, "tokenRequest", {
			trustChain: provider.trustChain,
			endpoint: provider.config.metadata.openid_provider.token_endpoint,
			request: requestObject,
		});

		const response = await axios({
			method: "POST",
			url: provider.config.metadata.openid_provider.token_endpoint,
			data: new URLSearchParams(requestObject),
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
		});

		// The IDP should return an access token and an ID token
		// eslint-disable-next-line camelcase
		const { access_token: accessToken, id_token } = response.data;

		// Grabbing the KID from the ID token
		let { header } = jwt.decode(id_token, { complete: true });

		// Verify the ID token with the provider's public key
		jwt.verify(
			id_token,
			provider.getKey(header.kid),
			{
				issuer: provider.config.iss,
				audience: this.clientID,
				maxAge: "3m",
				nonce: session.nonce,
			},
		);

		// Logging the response from the token endpoint and log the request to the userinfo endpoint
		this.logger(session.state, "tokenResponse", {
			trustChain: provider.trustChain,
			accessToken,
			idToken: id_token,
		});
		this.logger(session.state, "userInfoRequest", {
			trustChain: provider.trustChain,
			endpoint: provider.config.metadata.openid_provider.userinfo_endpoint,
		});

		// Now we can use the token to request the user's information
		const userInfoResponse = await axios({
			method: "GET",
			url: provider.config.metadata.openid_provider.userinfo_endpoint,
			headers: {
				Authorization: `Bearer ${accessToken.trim()}`,
			},
		});

		// The usertoken is returned as an encrypted JWT
		const decryptedUserInfo = await jose.compactDecrypt(
			userInfoResponse.data,
			this.keys.oidc.enc.private,
		);
		const userInfo: string = Buffer.from(decryptedUserInfo.plaintext).toString("utf-8");

		if (!userInfo) return { ok: false, error: "oidcErr" };

		// Extracting the KID from the decrypted JWT
		({ header } = jwt.decode(userInfo, { complete: true }));

		// Which contains the user's information as a JWT payload
		const decodedUserInfo: unknown = jwt.verify(
			userInfo,
			provider.getKey(header.kid),
		);

		// Mapping the user's attributes to the requested ones
		const userAttributes: Record<string, string> = this.attributes
			.reduce((a, c) => ({ ...a, [c]: decodedUserInfo[c] }), {});

		this.logger(session.state, "userInfoResponse", {
			trustChain: provider.trustChain,
			userinfo: userInfo,
		});

		// The user's information is in the response
		return {
			ok: true,
			payload: userAttributes,
		};
	}

	// ---- OIDC Federation Endpoint ---- //

	/**
	 * @typedef {Object} FederationOptions
	 * @property {boolean} json     Whether to return a JSON response instead of a JWT
	 * @property {string} jwks_uri  The URI to the JWKS endpoint, which will be included in the
	 *                              metadata
	 */
	/**
	 * Get the OIDC Federation endpoint for the IDP
	 *
	 * @param  federation_entity  Object that will be included in the federation_entity
	 *                            field of the federation
	 * @param  opts               Additional options
	 * @return                    The requested entity statement
	 */
	async federationEndpoint(
		federation_entity: {
			organization_name: string,
			contacts: string[],
		},
		opts: { json: boolean } = { json: false },
	): Promise<string | object> {
		const { json } = opts;

		const body = {
			iss: this.clientID,
			sub: this.clientID,
			// Federation keys
			jwks: { keys: this.getKeys("federation") },
			metadata: {
				// eslint-disable-next-line camelcase
				federation_entity,
				openid_relying_party: {
					application_type: "web",
					client_id: this.clientID,
					client_registration_types: ["automatic"],
					// eslint-disable-next-line camelcase
					client_name: federation_entity.organization_name,
					organization_name: federation_entity.organization_name,
					contacts: federation_entity.contacts,

					redirect_uris: [this.callbackURL],
					grant_types: ["authorization_code", "refresh_token"],
					response_types: ["code"],
					// OpenID keys
					jwks: { keys: this.getKeys("oidc") },
					// jwks_uri: `${this.clientID}jwks`,

					id_token_signed_response_alg: "RS256",
					userinfo_signed_response_alg: "RS256",
					userinfo_encrypted_response_alg: "RSA-OAEP",
					userinfo_encrypted_response_enc: "A128CBC-HS256",
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
			authority_hints: this.trustMarks.map(e => e.iss),
			trust_marks: this.trustMarks,
		};

		// If JSON mode is enabled, return a JSON response, not a JWT
		if (json) return body;

		return jwt.sign(
			body,
			this.keys.federation.sig.private,
			{
				expiresIn: "1h",
				keyid: this.keys.federation.sig.kid,
				header: {
					typ: "entity-statement+jwt",
					alg: "RS256",
				},
			},
		);
	}

	// ---- Utility functions

	/**
	 * Get the trust anchor entity configuration for the given sub, automatically fetching it if
	 * necessary
	 *
	 * @param  sub  The trust anchor entity ID
	 */
	private async getTrustAnchor(sub: string): Promise<JwtPayload> {
		if (this.trustAnchors.has(sub)) return this.trustAnchors.get(sub);

		console.info(`[oidc-ts] Fetching trust anchor entity configuration for ${sub}`);
		try {
			const ec = await getEntityConfiguration(sub);
			this.trustAnchors.set(sub, ec, ec.exp - Date.now() / 1000);
			return ec;
		}
		catch (e) {
			console.error(e);
			throw new Error(`Unable to fetch the trust anchor entity configuration for ${sub}`);
		}
	}

	/**
	 * Get the information about a provider, automatically validating it if necessary, otherwise
	 * returning the cached version
	 *
	 * @param idp   Identity provider ID (as defined in the configuration)
	 * @throws 	 If it's not possibile to find the provider, its configuration or validating it
	 * @return   The provider object
	 */
	async getProvider(idp: string): Promise<ParsedIDP> {
		if (!this.originalProviders.some(e => e.id === idp)) throw new Error("Invalid IDP");

		// Check if the provider is already in the cache
		let provider: ParsedIDP | undefined = this.providers.get(idp);

		// If it's present and not expired, return it
		if (provider && provider.ec) return provider;

		// Otherwise, validate the provider and save it in the cache
		// @ts-expect-error The provider is not in the cache, we are going to add the properties
		// necessary from the original provider (IDP) to make it a ParsedIDP
		provider = this.originalProviders.find(e => e.id === idp);

		// Decode the JWT and save the configuration
		provider.ec = await getEntityConfiguration(provider.entityID);

		// Create a getKey helper function for the provider that simply returns the key from the JWKS
		provider.getKey = (kid: string) => {
			const key = [
				...provider.ec.jwks.keys,
				...provider.ec.metadata.openid_provider.jwks.keys,
			].find(e => e.kid === kid);
			if (!key) throw new Error("Missing key");

			return crypto.createPublicKey({ key, format: "jwk" });
		};

		// If the provider has `dangerous_disableTrustChainValidation` set to true we can skip the
		// trust chain validation
		if (provider.dangerous_disableTrustChainValidation) {
			if (provider.dangerous_disableTrustChainValidation) console.warn(`[oidc-ts] Skipping trust chain validation for IDP ${provider.entityID}`);
			this.providers.set(idp, provider, 60 * 60);
			return provider;
		}

		/**
		 * - Validate the trust chain for this IDP
		 *
		 * This is done by trying to find at least one trust anchor that validates the trust chain
		 * for the IDP.
		 */
		const validTrustChain = await Promise.allSettled(this.originalTrustAnchors.map(async t => {
			// So, let's start by fetching the trust anchor's EC
			const trustAnchorEC = await this.getTrustAnchor(t);

			// Then we'll try to fetch the current IDP's EC through the trust anchor
			const idpEC = await getEntityConfigurationFromAnchor(trustAnchorEC, provider.entityID);

			const exp = Math.max(trustAnchorEC.exp, idpEC.exp);

			console.info(`[oidc-ts] Was able to find a valid trust chain for IDP ${provider.entityID} through trust anchor ${t}`);
			// If we got here, the trust chain is valid
			return {
				exp,
				chain: [
					provider.ec.raw() as string,
					idpEC.raw() as string,
					trustAnchorEC.raw() as string,
				],
			};
		}));

		if (!validTrustChain.some(e => e.status === "fulfilled")) throw new Error("Invalid trust chain");

		// Find the trust chain with the lowest exp value
		// Eslint is reporting a false negative here: not reporing a compile error
		// eslint-disable-next-line
		// @ts-ignore
		const shortestChain = validTrustChain.filter(e => e.status === "fulfilled").sort((a, b) => a.value.exp - b.value.exp)[0].value;

		// Also saving the trust chain in the cache for logging purposes
		provider.trustChain = shortestChain.chain;

		// Save the provider in the cache
		this.providers.set(idp, provider, shortestChain.exp - Date.now() / 1000);

		return provider;
	}
}
