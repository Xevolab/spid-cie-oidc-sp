/*
 * Author    : Francesco
 * Created at: 2024-10-12 21:37
 * Edited by : Francesco
 * Edited at : 2024-10-12 22:31
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

/**
 * A collection of utilities for OIDC
 */

import crypto from "crypto";

import axios, { AxiosResponse } from "axios";
import jwt, { JwtPayload } from "jsonwebtoken";

import { JWK } from "./types";

/**
 * Validate the entity configuration JWT string by validing that the signature is made using the
 * provided public key.
 *
 * @param   entityConfiguration  JWT string containing the entity configuration
 * @param   superior             If provided, the entity configuration signature will be validated
 * 									   using the public key of the superior entity
 */
export function validateEntityConfiguration(
	entityConfiguration: string,
	superior?: JwtPayload,
): boolean {
	const { header, payload } = jwt.decode(entityConfiguration, { complete: true });

	const ec = payload as JwtPayload & {
		iss: string,
		sub: string,
		jwks: {
			keys: JWK[],
		},
	};

	if (!ec) return false;
	if (
		(!ec && !(superior && superior.jwks))
		|| (!superior && !ec.jwks)
	) throw new Error("Unable to find usable jwks object");

	// Validate the EC with the public key
	const trustJwk = (superior || ec).jwks.keys.find((e: JWK) => e.kid === header.kid);
	if (!trustJwk) throw new Error("Unable to find signing key");

	const trustKey = crypto.createPublicKey({ key: trustJwk, format: "jwk" });
	if (!jwt.verify(entityConfiguration, trustKey)) return false;

	return true;
}

/**
 * Get the entity configuration for a specified entity by getting its openid-federation metadata
 * @param sub  The identitifier of the entity (url)
 */
export async function getEntityConfiguration(sub: string): Promise<JwtPayload> {
	let wellKnown: AxiosResponse;
	try {
		// ignore certificate errors
		wellKnown = await axios.get(`${sub + (sub.endsWith("/") ? "" : "/")}.well-known/openid-federation`);
	}
	catch (e) {
		// console.error(e);
		throw new Error(`Unable to get entity configuration for ${sub}`);
	}

	if (!wellKnown.headers["content-type"]?.startsWith("application/entity-statement+jwt")) throw new Error("Invalid EC content type");

	// Validate the EC of the IDP
	if (!validateEntityConfiguration(wellKnown.data)) throw new Error("Invalid EC signature");

	const r = jwt.decode(wellKnown.data) as JwtPayload;
	r.raw = (): string => wellKnown.data;

	return r;
}

export async function getEntityConfigurationFromAnchor(
	anchor: JwtPayload,
	sub: string,
): Promise<JwtPayload> {
	let wellKnown: AxiosResponse;
	try {
		// ignore certificate errors
		wellKnown = await axios.get(`${anchor.metadata.federation_entity.federation_fetch_endpoint}?sub=${sub}`);
	}
	catch (e) {
		// console.error(e);
		throw new Error(`Unable to get entity configuration for ${sub} through fetch endpoint ${anchor.sub}`);
	}

	if (!wellKnown.headers["content-type"]?.startsWith("application/entity-statement+jwt")) throw new Error("Invalid EC content type");

	// Validate the EC signature with the anchor's public key
	if (!validateEntityConfiguration(wellKnown.data, anchor)) throw new Error("Invalid EC signature");

	const r = jwt.decode(wellKnown.data) as JwtPayload;
	r.raw = (): string => wellKnown.data;

	return r;
}
