#-----------------------------------------------------------------------------------------------------------------------------------
using namespace System
using namespace System.Net

#requires -Module PSJsonWebToken

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

[string]$body = @{status = "Access denied" } | ConvertTo-Json;
[HttpStatusCode]$statusCode = [HttpStatusCode]::OK;

# Get JKU:
[string]$jwkUri = $env:JWK_URI;
if ($Request.Query.uri) {
    $jwkUri = $Request.Query.uri;
}

# Write to the Azure Functions log stream:
Write-Host "ValidateJwt function processed a request.";

# Attempt to get JWT from header:
[string]$authHeader = $Request.Headers['Authorization'];

try {
    if ($authHeader -match "Bearer") {
        $jwt = ($authHeader -split " ")[1];

        [bool]$isAuthenticated = Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -Uri $jwkUri -ErrorAction Stop;
        if ($isAuthenticated) {
            $body = @{status = "Authenticated" } | ConvertTo-Json;
        }
    }
}
catch {
    $statusCode = [HttpStatusCode]::Forbidden;
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $statusCode;
        Body       = $body;
    })
#-----------------------------------------------------------------------------------------------------------------------------------