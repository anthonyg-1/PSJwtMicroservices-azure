# PSJwtMicroservices-azure
Proof-of-concept Azure functions written in PowerShell that demonstrate creation and validation of a JSON Web Token via the PSJsonWebToken PowerShell module.

## Description
The three PowerShell scripts in this repository represent three different Azure functions.

### getjwt
Takes an API key and if valid, returns a JSON Web Token. The API key, private key to sign the JWT and claims for the token should be in Azure Key Vault. 

### validatejwt
Takes a JWT and validates it against a JWK set URI found in the configuration settings for the Azure function app.

### getjwkset
Looks to the configuration settings for a JWK set URI and adds our own JWK to this collection. This is potentially useful in the case where a service provider can only validate JSON Web Tokens against a single JSON Web Key set URI.
