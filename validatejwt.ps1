using namespace System
using namespace System.Net

#requires -Module PSJsonWebToken

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

[string]$body = @{status = "Access denied" } | ConvertTo-Json;
[HttpStatusCode]$statusCode = [HttpStatusCode]::OK;

# Get JKU:
[string]$jwkUri = $env:JWK_URI;

# Write to the Azure Functions log stream:
Write-Host "ValidateJwt function processed a request.";

# Attempt to get JWT from header:
[string]$authHeader = $Request.Headers['Authorization'];

try {
    if ($authHeader -match "Bearer") {
        $jwt = ($authHeader -split " ")[1];

        # Determine the signing algorithm:
        $algConversionTable = @{RS256 = "SHA256"; RS384 = "SHA384"; RS512 = "SHA512" }
        $discoveredAlg = $jwt | Get-JsonWebTokenHeader | Select-Object -ExpandProperty alg

        [string]$algToUse = ""
        if ($discoveredAlg -in $algConversionTable.Keys) {
            $algToUse = $algConversionTable.Item($discoveredAlg)

            [bool]$isAuthenticated = Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm $algToUse -Uri $jwkUri -ErrorAction Stop;
            if ($isAuthenticated) {
                $claims = Get-JsonWebTokenPayload -JsonWebToken $jwt
                $body = [ordered]@{status = "Authenticated"; claims = $claims } | ConvertTo-Json;
            }
        }
        else {
            $body = $body = [ordered]@{status = "Access denied"; reason = "Invalid algorithm specified" } | ConvertTo-Json;
            $statusCode = [HttpStatusCode]::Forbidden;
        }
    }
    else {
        throw "Missing Bearer token";
    }
}
catch {
    $statusCode = [HttpStatusCode]::Forbidden;
}

$responseHeaders = @{'Content-Type' = 'application/json; charset=utf-8';
    'Strict-Transport-Security'     = 'max-age=31536000; includeSubDomains';
    'Content-Security-Policy'       = "default-src 'self'";
    'X-Content-Type-Options'        = 'nosniff';
    'X-Frame-Options'               = "SAMEORIGIN";
    'Referrer-Policy'               = 'no-referrer-when-downgrade'
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $statusCode;
        Body       = $body;
        Headers    = $responseHeaders;
    })
