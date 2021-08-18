using namespace System
using namespace System.Net
using namespace System.Security.Cryptography.X509Certificates


#!!! THIS FUNCTION ASSUMES THAT YOUR AZURE FUNCTION IS CONFIGURED WITH FUNCTION AUTHENTICATION !!!#

#requires -Module PSJsonWebToken

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

[string]$body = @{status = "Access denied" } | ConvertTo-Json;
[HttpStatusCode]$statusCode = [HttpStatusCode]::Forbidden;

# Environment variables below. First three should be in Azure Key Vault!
$base64Cert = $env:JWT_PFX;
$tokenClaims = $env:JWT_CLAIMS;
$jwtTtl = $env:JWT_TTL;
$nbfSkew = $env:JWT_NBF_SKEW;

# Write to the Azure Functions log stream:
Write-Host "getjwt function processed a request.";

# Convert base 64 string to byte array and ultimately to X509Certfifcate2 object:
[byte[]]$certificateBytes = [Convert]::FromBase64String($base64Cert);
$certificate = [X509Certificate2]::new($certificateBytes, $null);

# Pull claims from environment variable, and convert to hash table to pass to New-JsonWebToken:
$claims = $tokenClaims | ConvertFrom-Json -AsHashTable;

# Generate JWT:
[string]$jwt = "";
try {
    $jwt = New-JsonWebToken -Claims $claims -HashAlgorithm SHA256 -NotBeforeSkew $nbfSkew -AddJtiClaim -SigningCertificate $certificate -TimeToLive $jwtTtl -ErrorAction Stop;
    $statusCode = [HttpStatusCode]::OK;
    $body = $jwt;
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
