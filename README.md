# PSJwtMicroservices-azure
Proof-of-concept Azure functions written in PowerShell that demonstrate creation and validation of a JSON Web Token via the PSJsonWebToken PowerShell module.

## Description
The three PowerShell scripts in this repository represent three different Azure functions.

### getjwt
Takes an API key and if valid, returns a JSON Web Token. The API key, private key to sign the JWT and claims for the token should be in Azure Key Vault. 

### validatejwt
Takes a JWT and validates it against a JWK set URI found in the configuration settings for the Azure function app.
