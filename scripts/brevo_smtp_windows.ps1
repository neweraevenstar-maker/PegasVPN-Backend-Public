# PegasVPN: send one non-OTP Brevo test email from the owner's Windows PC.
# Default: offline; no network, credentials, file writes or production changes.
# Explicit -Send: prompt for SMTP login and hidden key, then send one message.
[CmdletBinding()]
param(
    [switch]$Send,
    [string]$Recipient = "admin@vimvitae.net"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $Send) {
    Write-Output "OFFLINE ONLY: no credentials requested and no email sent."
    Write-Output "To send one test: .\scripts\brevo_smtp_windows.ps1 -Send"
    exit 0
}

$client = $null
$message = $null
$secret = $null
try {
    if ($Recipient -notmatch '\A[^@\s]+@[^@\s]+\.[^@\s]+\z') {
        throw "Invalid recipient email"
    }

    Write-Output "One test message: noreply@vimvitae.net -> $Recipient"
    $login = Read-Host "Brevo SMTP login (NOT your Brevo account email)"
    if ([string]::IsNullOrWhiteSpace($login) -or $login -match '[\r\n]') {
        throw "Invalid SMTP login"
    }
    $secret = Read-Host "Brevo SMTP key (hidden)" -AsSecureString
    if ($secret.Length -eq 0) {
        throw "Empty SMTP key"
    }

    $client = [System.Net.Mail.SmtpClient]::new("smtp-relay.brevo.com", 587)
    $client.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
    $client.EnableSsl = $true  # STARTTLS; certificate checked by .NET
    $client.UseDefaultCredentials = $false
    $client.Credentials = [System.Net.NetworkCredential]::new($login, $secret)
    $client.Timeout = 15000

    $message = [System.Net.Mail.MailMessage]::new(
        "noreply@vimvitae.net",
        $Recipient,
        "PegasVPN: Brevo SMTP test (not a login code)",
        "This is a delivery test. It is NOT a login code. No action is required."
    )
    $client.Send($message)
    Write-Output "SMTP accepted one test email. Confirm inbox receipt and Brevo event status."
}
catch {
    # Do not print exception/server response: may contain sensitive details.
    [Console]::Error.WriteLine(
        "Brevo SMTP test failed. Check login/key, SMTP activation, TLS/network and sender."
    )
    exit 1
}
finally {
    if ($null -ne $message) { $message.Dispose() }
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $secret) { $secret.Dispose() }
}
