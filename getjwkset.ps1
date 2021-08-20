using namespace System
using namespace System.Net
using namespace System.Security.Cryptography.X509Certificates

#requires -Module PSJsonWebToken

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Default return value and HTTP status code:
[string]$body = @{status = "Access denied" } | ConvertTo-Json;
[HttpStatusCode]$statusCode = [HttpStatusCode]::Forbidden;

# Environment variables: 
$base64Cert = $env:JWT_PFX;
$responseHeaders = $env:RESPONSE_HEADERS | ConvertFrom-Json -AsHashtable;

# Write to the Azure Functions log stream.
Write-Host "jwks function processed a request.";

$jwkCollection = $null;
try {
    # Convert base 64 string to byte array and ultimately to X509Certfifcate2 object:
    [byte[]]$certificateBytes = [Convert]::FromBase64String($base64Cert);
    $certificate = [X509Certificate2]::new($certificateBytes, $null);

    # Convert the X509Certificate2 into a JWK set:
    $jwkSet = $certificate | New-JsonWebKeySet -Compress;

    $statusCode = [HttpStatusCode]::OK;
    
    $body = $jwkSet;
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
