using namespace System
using namespace System.Net
using namespace System.Security.Cryptography.X509Certificates

#requires -Module PSJsonWebToken

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

[string]$body = @{keys = $null } | ConvertTo-Json;
[HttpStatusCode]$statusCode = [HttpStatusCode]::OK;

$base64Cert = $env:JWT_PFX;

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
