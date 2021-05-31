using namespace System
using namespace System.Net
using namespace System.Security.Cryptography.X509Certificates

#requires -Module PSJsonWebToken

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

[string]$body = @{status = "Access denied" } | ConvertTo-Json;
[HttpStatusCode]$statusCode = [HttpStatusCode]::OK;

# Environment variables below. First three should be in Azure Key Vault!
$base64Cert = $env:JWT_PFX;
$validationKey = $env:JWT_SECRET;
$tokenClaims = $env:JWT_CLAIMS;
$jwtTtl = $env:JWT_TTL;
$nbfSkew = $env:JWT_NBF_SKEW;

# Write to the Azure Functions log stream:
Write-Host "GetJwt function processed a request.";

# Attempt to get X-API-KEY:
$key = $Request.Headers["X-API-KEY"];
if (-not $key) {
    $key = $Request.Body['X-API-KEY'];
}

# If proper key is passed, attempt to craft JWT:
if ($key -eq $validationKey) {
    # Convert base 64 string to byte array and ultimately to X509Certfifcate2 object:
    [byte[]]$certificateBytes = [Convert]::FromBase64String($base64Cert);
    $certificate = [X509Certificate2]::new($certificateBytes, $null);

    # Pull claims from environment variable, and convert to hash table to pass to New-JsonWebToken:
    $claims = $tokenClaims | ConvertFrom-Json -AsHashTable;

    # Generate JWT:
    [string]$jwt = "";
    try {
        $jwt = New-JsonWebToken -Claims $claims -HashAlgorithm SHA256 -NotBeforeSkew $nbfSkew -AddJtiClaim -SigningCertificate $certificate -TimeToLive $jwtTtl -ErrorAction Stop;
        $body = $jwt;
    }
    catch {
        $statusCode = [HttpStatusCode]::Forbidden;
    }
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $statusCode;
        Body       = $body;
    })
