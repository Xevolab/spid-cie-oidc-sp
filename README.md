<p align="center">
    <h2 align="center">SPID/CIE OIDC Service Provider</h2>
</p>

<p align="center">
  Integrate with SPID and CIE authentication using the OIDC federation protocol.
</p>

<hr />

<p align="center">
  <a href="https://docs.xevolab.dev/spid-cie-oidc-ts"><strong>Documentation</strong></a> ·
  <a href="https://github.com/xevolab/spid-cie-oidc-ts/releases"><strong>Releases</strong></a>
</p>
<p align="center">
	<img src="https://img.shields.io/github/package-json/v/xevolab/spid-cie-oidc-ts/main?label=Version" />
	<a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg" alt="Apache 2.0 License" /></a>
	<img src="https://shields.io/badge/TypeScript-3178C6?logo=TypeScript&logoColor=FFF" />
</p>

> [!NOTE]
> This library is still in development, all feedback is welcome!

> [!WARNING]
> At this moment, SPID does not officially support the OIDC federation protocol.

Let your users to authenticate with SPID and CIE using the OIDC federation protocol in your applications, with a simple and easy-to-use library. And also TypeScript compatible.

## Installation

```bash
npm install @xevolab/spid-cie-oidc-ts
```

## Usage

### Creating a key set

The object passed to the OIDCClient constructor must contain two key sets. These keys are used to:

- Sign, verify and encrypt the JWTs exchanged with the OIDC provider
- Sign and verify the OIDC federation manifest

```javascript
const keys = {
	oidc: {
		sig: {
			public:  "-----BEGIN PUBLIC KEY-----...",
			private: "-----BEGIN RSA PRIVATE KEY-----..."
		},
		enc: {
			public:  "-----BEGIN PUBLIC KEY-----...",
			private: "-----BEGIN RSA PRIVATE KEY-----..."
		},
	},
	federation: {
		sig: {
			public:  "-----BEGIN PUBLIC KEY-----...",
			private: "-----BEGIN RSA PRIVATE KEY-----..."
		}
	}
};
```

If a specific set of federation sig key is not provided, the library will use the OIDC sig key.

### Initializing the Client

```javascript
import OIDCClient, { devTrustAnchors, prodTrustAnchors } from 'oidc-client-library';

const client = new OIDCClient({
  clientID:  process.env.APP_FULL_URL,
	providers: [{
		id: "cie",
		wellKnown: "https://preproduzione.oidc.idserver.servizicie.interno.gov.it/.well-known/openid-federation"
	}],
	keys,
	callbackURL:  process.env.APP_FULL_URL + "/callback",
	spidLevel: 2,
	attributes: ["given_name", "family_name", "email", "birthdate", "https://attributes.eid.gov.it/fiscal_number"],
	trustAnchors: devTrustAnchors,
	trustMarks: [{
		"id": "",
		"iss": "",
		"trust_mark": "eyJ..."
	}],
	logger: (state, action, payload) => { /* ... */ }
});
```

### Starting the Authentication Flow

```javascript
const authResponse = client.authorization(providerID);
if (authResponse.ok) {
  // Redirect the user to the URL provided in authResponse.url
}
```

### Handling the Callback

```javascript
// Grab the state, code, and iss parameters from the callback URL query string
const callbackResponse = await client.callback({ state, code, iss });

if (callbackResponse.ok) {
  // Handle successful authentication
} else {
  // Handle errors
}
```
