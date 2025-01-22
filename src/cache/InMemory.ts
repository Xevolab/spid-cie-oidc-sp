/*
 * Author    : Francesco
 * Created at: 2025-01-21 10:20
 * Edited by : Francesco
 * Edited at : 2025-01-21 10:34
 *
 * Copyright (c) 2025 Xevolab S.R.L.
 */

import NodeCache from "node-cache";

export default class InMemory<T> {
	cache = new NodeCache({ stdTTL: 60 * 3, checkperiod: 60 * 3 * 2 });

	constructor() {
		console.warn("Using an in-memory cache. This is not suitable for production environments as it can lead to performance drawbacks and cannot be shared by multiple instances of your application.");
	}

	/**
	 * Upsert a value in the cache
	 */
	async upsert(key: string, value: T, ttl?: number): Promise<void> {
		this.cache.set(key, value, ttl || 60 * 3);
	}

	/**
	 * Get a value from the cache
	 */
	async get(key: string): Promise<T> {
		return this.cache.get(key) as T;
	}

	/**
	 * Get a value from the cache and remove it
	 */
	async take(key: string): Promise<T> {
		const value = this.cache.get(key) as T;
		this.cache.del(key);
		return value;
	}

}
