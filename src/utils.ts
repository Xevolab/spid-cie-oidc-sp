/*
 * Author    : Francesco
 * Created at: 2024-10-12 21:19
 * Edited by : Francesco
 * Edited at : 2024-10-12 22:31
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

import crypto from "crypto";

import {
	KeyPair, UseKeyPair, ParsedKeyPair,
} from "./types";

/**
 * Compute the key ID for the given use
 *
 * @param key The public key in PEM string format
 * @return The key ID as a base64url string
 */
export function getKeyID(key: KeyPair["public"]): string {
	const jsonKey = crypto.createPublicKey({ key, format: "pem", type: "spki" }).export({ format: "jwk" });

	return crypto.createHash("sha256").update(JSON.stringify({
		e: jsonKey.e,
		kty: jsonKey.ktw,
		n: jsonKey.n,
	})).digest("base64url");
}

/**
 * Transform the key object into a Node crypto key object
 *
 * @param key An object containing the public and private keys for sig and enc purposes
 * @param name The name to give the key pair
 * @return The parsed key object
 */
export function parseKeyObject(key: UseKeyPair, name: string = "oidc"): {
	sig: ParsedKeyPair,
	enc?: ParsedKeyPair,
} {
	return {
		sig: {
			name,
			use: "sig",
			alg: "RS256",
			public: crypto.createPublicKey({ key: key.sig.public, format: "pem", type: "spki" }),
			private: crypto.createPrivateKey(key.sig.private),
			kid: getKeyID(key.sig.public),
		},
		enc: key.enc ? {
			name,
			use: "enc",
			alg: "RSA-OAEP",
			public: crypto.createPublicKey({ key: key.enc.public, format: "pem", type: "spki" }),
			private: crypto.createPrivateKey(key.enc.private),
			kid: getKeyID(key.enc.public),
		} : undefined,
	};
}
