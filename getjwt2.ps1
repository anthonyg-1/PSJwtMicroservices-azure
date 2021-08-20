using namespace System
using namespace System.Net
using namespace System.Security.Cryptography.X509Certificates

#requires -Module PSJsonWebToken

#!!! THIS FUNCTION ASSUMES THAT YOUR AZURE FUNCTION IS CONFIGURED WITH FUNCTION AUTHENTICATION !!!

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Default return value and HTTP status code:
[string]$body = @{status = "Access denied" } | ConvertTo-Json;
[HttpStatusCode]$statusCode = [HttpStatusCode]::Forbidden;

# Environment variables below. First two should be in Azure Key Vault!
$base64Cert = $env:JWT_PFX;
$tokenClaims = $env:JWT_CLAIMS | ConvertFrom-Json -AsHashTable;
$jwtTtl = $env:JWT_TTL;
$nbfSkew = $env:JWT_NBF_SKEW;
$responseHeaders = $env:RESPONSE_HEADERS | ConvertFrom-Json -AsHashtable;

# Write to the Azure Functions log stream:
Write-Host "getjwt function processed a request.";

try {
    # Convert base 64 string to byte array and ultimately to X509Certfifcate2 object:
    [byte[]]$certificateBytes = [Convert]::FromBase64String($base64Cert);
    $certificate = [X509Certificate2]::new($certificateBytes, $null);

    $jwt = New-JsonWebToken -Claims $tokenClaims -HashAlgorithm SHA256 -NotBeforeSkew $nbfSkew -AddJtiClaim -SigningCertificate $certificate -TimeToLive $jwtTtl -ErrorAction Stop;

    $statusCode = [HttpStatusCode]::OK;

    $body = $jwt;
}
catch {
    $errorMessage = $_.Exception.Message;
    Write-Host $errorMessage;
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $statusCode;
        Body       = $body;
        Headers    = $responseHeaders;
    })
