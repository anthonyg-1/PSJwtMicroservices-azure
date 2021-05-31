using namespace System
using namespace System.Net
using namespace System.Security.Cryptography.X509Certificates

#requires -Module PSJsonWebToken

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

[string]$body = @{keys = $null} | ConvertTo-Json;
[HttpStatusCode]$statusCode = [HttpStatusCode]::OK;

# Get JKU and public key:
$jwkUri = $env:JWK_URI;
$base64Cert = $env:JWT_PEM;

# Write to the Azure Functions log stream.
Write-Host "GetJwkSet function processed a request.";

$jwkCollection = $null;
try {
    # Get the existing JWK collection we wish to add to:
    $jwkCollection = Get-JwkCollection -Uri $jwkUri -ErrorAction Stop;


    # Convert base 64 string to byte array and ultimately to X509Certfifcate2 object:
    [byte[]]$certificateBytes = [Convert]::FromBase64String($base64Cert);
    $certificate = [X509Certificate2]::new($certificateBytes, $null);

    # Convert the X509Certificate2 into a JWK object:
    $jwk = $certificate | New-JsonWebKey;

    # Add our JWK to the collection:
    $jwkCollection+= $jwk;

    # Serialize and assign to the $body variable to return:
    $jwkSet = @{keys=$jwkCollection};
    $body = $jwkSet | ConvertTo-Json;
}
catch {
    $statusCode = [HttpStatusCode]::Forbidden;
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $statusCode;
        Body       = $body;
    })
