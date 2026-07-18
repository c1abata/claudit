<#
    Connection.ps1 - establishes read-only sessions to Microsoft Graph and
    Exchange Online.

    Design rules:
      * Read-only scopes only. Claudit never requests write permissions.
      * Two auth models: interactive delegated (default, for an admin at a
        keyboard) and app-only with a certificate (for unattended/scheduled
        runs). Never client secrets.
      * National clouds supported via -Environment (Maester parity).
      * Modules are imported lazily so the suite stays loadable for inspection
        on a machine that has not installed the dependencies yet.
#>

# Minimal read-only delegated scopes required by the checks.
$script:CaGraphScopes = @(
    'Directory.Read.All',
    'Policy.Read.All',
    'RoleManagement.Read.Directory',
    'Application.Read.All',
    'Organization.Read.All',
    'User.Read.All',
    'SharePointTenantSettings.Read.All'
)

# Map a friendly environment name to the Graph and Exchange equivalents.
$script:CaEnvironmentMap = @{
    'Global'   = @{ Graph = 'Global';   GraphRoot = 'https://graph.microsoft.com';              LoginRoot = 'https://login.microsoftonline.com';        Exo = 'O365Default' }
    'USGov'    = @{ Graph = 'USGov';     GraphRoot = 'https://graph.microsoft.us';               LoginRoot = 'https://login.microsoftonline.us';         Exo = 'O365USGovGCCHigh' }
    'USGovDOD' = @{ Graph = 'USGovDOD';  GraphRoot = 'https://dod-graph.microsoft.us';           LoginRoot = 'https://login.microsoftonline.us';         Exo = 'O365USGovDoD' }
    'China'    = @{ Graph = 'China';     GraphRoot = 'https://microsoftgraph.chinacloudapi.cn';   LoginRoot = 'https://login.chinacloudapi.cn';           Exo = 'O365China' }
}

$script:CaGraphPowerShellClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

$script:CaState = [pscustomobject]@{
    GraphConnected    = $false
    ExchangeConnected = $false
    TenantId          = $null
    Environment       = 'Global'
    GraphRoot         = 'https://graph.microsoft.com'
    ConnectedAtUtc    = $null
}

function Import-CaModule {
    param([Parameter(Mandatory)][string]$Name)
    if (Get-Module -Name $Name) { return }
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Required module '$Name' is not installed. Install it with: Install-Module $Name -Scope CurrentUser"
    }
    Import-Module $Name -ErrorAction Stop -Verbose:$false | Out-Null
}

function ConvertTo-CaBase64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-CaPkcePair {
    $verifierBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
    $verifier = ConvertTo-CaBase64Url -Bytes $verifierBytes

    $challengeBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($verifier))
    [pscustomobject]@{
        Verifier  = $verifier
        Challenge = ConvertTo-CaBase64Url -Bytes $challengeBytes
    }
}

function ConvertFrom-CaQueryString {
    param([AllowNull()][string]$Query)

    $result = @{}
    if ([string]::IsNullOrWhiteSpace($Query)) { return $result }
    foreach ($pair in $Query.TrimStart('?') -split '&') {
        if ([string]::IsNullOrWhiteSpace($pair)) { continue }
        $parts = $pair -split '=', 2
        $name = [System.Net.WebUtility]::UrlDecode($parts[0])
        $value = if ($parts.Count -gt 1) { [System.Net.WebUtility]::UrlDecode($parts[1]) } else { '' }
        $result[$name] = $value
    }
    return $result
}

function New-CaGraphBrowserAuthRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Scopes,
        [Parameter(Mandatory)][ValidateSet('Global', 'USGov', 'USGovDOD', 'China')][string]$Environment,
        [Parameter(Mandatory)][string]$RedirectUri,
        [string]$Tenant = 'organizations'
    )

    $env = $script:CaEnvironmentMap[$Environment]
    $pkce = New-CaPkcePair
    $stateBytes = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($stateBytes)
    $state = ConvertTo-CaBase64Url -Bytes $stateBytes
    $graphScopes = @($Scopes | ForEach-Object {
        if ($_ -match '^https://') { $_ } else { "$($env.GraphRoot.TrimEnd('/'))/$_" }
    })
    $scope = (@('openid', 'profile') + $graphScopes) -join ' '

    $query = @{
        client_id             = $script:CaGraphPowerShellClientId
        response_type         = 'code'
        redirect_uri          = $RedirectUri
        response_mode         = 'query'
        scope                 = $scope
        state                 = $state
        prompt                = 'select_account'
        code_challenge        = $pkce.Challenge
        code_challenge_method = 'S256'
    }
    $encoded = @($query.GetEnumerator() | Sort-Object Name | ForEach-Object {
        '{0}={1}' -f [System.Net.WebUtility]::UrlEncode($_.Key), [System.Net.WebUtility]::UrlEncode([string]$_.Value)
    }) -join '&'

    [pscustomobject]@{
        AuthUri       = "$($env.LoginRoot)/$Tenant/oauth2/v2.0/authorize?$encoded"
        TokenEndpoint = "$($env.LoginRoot)/$Tenant/oauth2/v2.0/token"
        RedirectUri   = $RedirectUri
        State         = $state
        CodeVerifier  = $pkce.Verifier
        Scope         = $scope
    }
}

function Get-CaBrowserExecutable {
    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @('msedge.exe', 'chrome.exe', 'brave.exe')) { $candidates.Add($name) }
    foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA)) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $candidates.Add((Join-Path $root 'Microsoft\Edge\Application\msedge.exe'))
        $candidates.Add((Join-Path $root 'Google\Chrome\Application\chrome.exe'))
        $candidates.Add((Join-Path $root 'BraveSoftware\Brave-Browser\Application\brave.exe'))
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $cmd = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Start-CaTemporaryBrowser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$ProfilePath
    )

    $browser = Get-CaBrowserExecutable
    if (-not $browser) {
        throw 'Browser auth requires Microsoft Edge, Chrome or Brave so Claudit can use a temporary profile. Use -GraphAuthMode DeviceCode on this workstation.'
    }

    if (-not (Test-Path -LiteralPath $ProfilePath)) {
        New-Item -ItemType Directory -Path $ProfilePath -Force | Out-Null
    }

    $args = @("--user-data-dir=$ProfilePath", '--new-window', '--no-first-run', '--no-default-browser-check', $Uri)
    Start-Process -FilePath $browser -ArgumentList $args -PassThru
}

function Read-CaOAuthRedirectCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Net.Sockets.TcpListener]$Listener,
        [Parameter(Mandatory)][string]$ExpectedState,
        [int]$TimeoutSeconds = 300
    )

    $accept = $Listener.AcceptTcpClientAsync()
    if (-not $accept.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
        throw "Timed out waiting for browser authentication callback after $TimeoutSeconds seconds."
    }

    $client = $accept.Result
    try {
        $stream = $client.GetStream()
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8, $false, 4096, $true)
        $requestLine = $reader.ReadLine()
        if ([string]::IsNullOrWhiteSpace($requestLine)) { throw 'Empty browser callback.' }
        $parts = $requestLine -split ' ', 3
        if ($parts.Count -lt 2) { throw "Malformed browser callback: $requestLine" }

        while ($true) {
            $line = $reader.ReadLine()
            if ($null -eq $line -or $line -eq '') { break }
        }

        $uri = [uri]("http://localhost$($parts[1])")
        $query = ConvertFrom-CaQueryString -Query $uri.Query
        $ok = $false
        $body = '<html><body><h1>Claudit authentication complete</h1><p>You can close this temporary browser window.</p></body></html>'
        if ($query.ContainsKey('error')) {
            $body = "<html><body><h1>Claudit authentication failed</h1><p>$([System.Net.WebUtility]::HtmlEncode($query['error_description']))</p></body></html>"
        }
        else {
            $ok = $true
        }

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $status = if ($ok) { '200 OK' } else { '400 Bad Request' }
        $header = "HTTP/1.1 $status`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
        $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
        $stream.Write($headerBytes, 0, $headerBytes.Length)
        $stream.Write($bytes, 0, $bytes.Length)

        if ($query.ContainsKey('error')) {
            throw "Browser authentication failed: $($query['error']) $($query['error_description'])"
        }
        if (-not $query.ContainsKey('state') -or $query['state'] -ne $ExpectedState) {
            throw 'Browser authentication state mismatch.'
        }
        if (-not $query.ContainsKey('code')) {
            throw 'Browser authentication callback did not include an authorization code.'
        }
        return $query['code']
    }
    finally {
        $client.Close()
    }
}

function Invoke-CaGraphTemporaryBrowserAuth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Scopes,
        [Parameter(Mandatory)][ValidateSet('Global', 'USGov', 'USGovDOD', 'China')][string]$Environment
    )

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $browserProcess = $null
    $profilePath = Join-Path ([System.IO.Path]::GetTempPath()) ("claudit-browser-" + [guid]::NewGuid().ToString('N'))
    try {
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $redirectUri = "http://localhost:$port/"
        $request = New-CaGraphBrowserAuthRequest -Scopes $Scopes -Environment $Environment -RedirectUri $redirectUri

        Write-Host 'Claudit: opening temporary browser profile for Microsoft Graph authentication...' -ForegroundColor Cyan
        $browserProcess = Start-CaTemporaryBrowser -Uri $request.AuthUri -ProfilePath $profilePath
        $code = Read-CaOAuthRedirectCode -Listener $listener -ExpectedState $request.State

        $token = Invoke-RestMethod -Method Post -Uri $request.TokenEndpoint -ContentType 'application/x-www-form-urlencoded' -Body @{
            client_id     = $script:CaGraphPowerShellClientId
            grant_type    = 'authorization_code'
            code          = $code
            redirect_uri  = $request.RedirectUri
            code_verifier = $request.CodeVerifier
            scope         = $request.Scope
        } -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($token.access_token)) {
            throw 'Browser authentication completed but no access token was returned.'
        }
        return (ConvertTo-SecureString ([string]$token.access_token) -AsPlainText -Force)
    }
    finally {
        $listener.Stop()
        if ($browserProcess -and -not $browserProcess.HasExited) {
            try { $browserProcess.CloseMainWindow() | Out-Null } catch {}
        }
        if (Test-Path -LiteralPath $profilePath) {
            Remove-Item -LiteralPath $profilePath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Connect-Claudit {
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(ParameterSetName = 'AppOnly', Mandatory)][string]$TenantId,
        [Parameter(ParameterSetName = 'AppOnly', Mandatory)][string]$ClientId,
        [Parameter(ParameterSetName = 'AppOnly', Mandatory)][string]$CertificateThumbprint,

        # Exchange Online is optional; skip if you only audit Entra/SharePoint.
        [switch]$SkipExchange,
        [switch]$SkipGraph,

        # Exchange app-only needs the tenant's onmicrosoft.com domain.
        [Parameter(ParameterSetName = 'AppOnly')][string]$Organization,

        # National cloud selection.
        [ValidateSet('Global', 'USGov', 'USGovDOD', 'China')]
        [string]$Environment = 'Global',

        # Browser/WAM is brittle in embedded terminals. DeviceCode is the
        # default for delegated Graph auth because it is explicit and terminal-safe.
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateSet('DeviceCode', 'Browser')]
        [string]$GraphAuthMode = 'DeviceCode'
    )

    $appOnly = $PSCmdlet.ParameterSetName -eq 'AppOnly'
    $env = $script:CaEnvironmentMap[$Environment]
    $script:CaState.Environment = $Environment
    Set-CaGraphRoot -Uri $env.GraphRoot

    if (-not $SkipGraph) {
        Import-CaModule -Name 'Microsoft.Graph.Authentication'
        $graphArgs = @{ NoWelcome = $true; ErrorAction = 'Stop' }
        if ($Environment -ne 'Global') { $graphArgs['Environment'] = $env.Graph }
        if ($appOnly) {
            $graphArgs['TenantId'] = $TenantId
            $graphArgs['ClientId'] = $ClientId
            $graphArgs['CertificateThumbprint'] = $CertificateThumbprint
        }
        else {
            if ($GraphAuthMode -eq 'DeviceCode') {
                $graphArgs['Scopes'] = $script:CaGraphScopes
                if (-not (Get-Command -Name Connect-MgGraph -ErrorAction Stop).Parameters.ContainsKey('UseDeviceCode')) {
                    throw 'Installed Microsoft.Graph.Authentication does not support Connect-MgGraph -UseDeviceCode. Update the module or use -GraphAuthMode Browser.'
                }
                $graphArgs['UseDeviceCode'] = $true
            }
            else {
                $graphArgs['AccessToken'] = Invoke-CaGraphTemporaryBrowserAuth -Scopes $script:CaGraphScopes -Environment $Environment
            }
        }
        try {
            Connect-MgGraph @graphArgs
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match 'InteractiveBrowserCredential|DeviceCodeCredential|Web Account Manager|WAM|WithLogging|Microsoft.Identity.Client|Microsoft.IdentityModel') {
                throw "Microsoft Graph authentication failed in the local PowerShell process: $msg. Use Start-ClauditSafeAudit.ps1, which launches the live audit in pwsh -NoProfile, or start a fresh PowerShell session. If it still fails in a clean process, reinstall/update Microsoft.Graph.Authentication."
            }
            throw
        }
        $ctx = Get-MgContext
        $script:CaState.GraphConnected = $true
        $script:CaState.TenantId = $ctx.TenantId
        Write-Verbose "Graph connected to tenant $($ctx.TenantId) as $($ctx.Account) [$Environment]."
    }

    if (-not $SkipExchange) {
        Import-CaModule -Name 'ExchangeOnlineManagement'
        $exoArgs = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($Environment -ne 'Global') { $exoArgs['ExchangeEnvironmentName'] = $env.Exo }
        if ($appOnly) {
            if (-not $Organization) {
                throw "Exchange app-only auth requires -Organization (e.g. contoso.onmicrosoft.com)."
            }
            $exoArgs['AppId'] = $ClientId
            $exoArgs['CertificateThumbprint'] = $CertificateThumbprint
            $exoArgs['Organization'] = $Organization
        }
        Connect-ExchangeOnline @exoArgs
        $script:CaState.ExchangeConnected = $true
        Write-Verbose 'Exchange Online connected.'
    }

    $script:CaState.ConnectedAtUtc = [DateTime]::UtcNow.ToString('o')
    return $script:CaState
}

function Disconnect-Claudit {
    [CmdletBinding()]
    param()
    if ($script:CaState.GraphConnected) {
        try { Disconnect-MgGraph -ErrorAction Stop | Out-Null } catch { Write-Verbose "Graph disconnect: $_" }
        $script:CaState.GraphConnected = $false
    }
    if ($script:CaState.ExchangeConnected) {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop } catch { Write-Verbose "Exchange disconnect: $_" }
        $script:CaState.ExchangeConnected = $false
    }
}

function Assert-CaGraph {
    if (-not $script:CaState.GraphConnected) {
        throw 'Not connected to Microsoft Graph. Run Connect-Claudit first.'
    }
}

function Assert-CaExchange {
    if (-not $script:CaState.ExchangeConnected) {
        throw 'Not connected to Exchange Online. Run Connect-Claudit (without -SkipExchange) first.'
    }
}

function Set-CaGraphRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)

    if ($script:CaState.PSObject.Properties.Name -contains 'GraphRoot') {
        $script:CaState.GraphRoot = $Uri
    }
    else {
        $script:CaState | Add-Member -NotePropertyName GraphRoot -NotePropertyValue $Uri
    }
}
