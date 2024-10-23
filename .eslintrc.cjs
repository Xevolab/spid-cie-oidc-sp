/*
 * Author    : Francesco
 * Created at: 2024-02-05 08:52
 * Edited by : Francesco
 * Edited at : 2024-10-12 19:18
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

module.exports = {
	root: true,
	extends: [
		"@xevolab/eslint-config/backend",
		"plugin:@typescript-eslint/recommended",
	],
	parser: "@typescript-eslint/parser",
	plugins: ["@typescript-eslint"],
	rules: {
		"import/extensions": [
			"error",
			"ignorePackages",
			{
				js: "never",
				ts: "never",
				jsx: "never",
				tsx: "never",
			},
		],
	},
	settings: {
		"import/resolver": {
			node: {
				extensions: [".js", ".ts"],
			},
		},
	},
};
