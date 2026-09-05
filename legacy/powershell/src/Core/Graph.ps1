<#
    Graph.ps1 - thin Microsoft Graph request helper (Maester-inspired).

    Invoke-CaGraphRequest issues a raw Graph call and transparently follows
    @odata.nextLink paging, returning the full collection. This lets EIDSCA-style
    checks read configuration endpoints (e.g. /policies/authenticationMethodsPolicy)
    that have no dedicated cmdlet, and guarantees large tenants are not silently
    truncated at the first page.

    Read-only: callers only ever issue GET.
#>

function Invoke-CaGraphRequest {
    [CmdletBinding()]
    param(
        # Relative path (e.g. 'policies/authorizationPolicy') or full URL.
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('v1.0', 'beta')][string]$ApiVersion = 'v1.0'
    )

    Assert-CaGraph

    if ($Uri -notmatch '^https?://') {
        $root = Get-CaGraphRoot
        $Uri = "$root/$ApiVersion/$($Uri.TrimStart('/'))"
    }

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop

        # Collection responses expose a 'value' array; single objects do not.
        if ($null -ne $resp -and ($resp.PSObject.Properties.Name -contains 'value')) {
            foreach ($v in $resp.value) { $items.Add($v) }
            $next = if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $resp.'@odata.nextLink' } else { $null }
        }
        else {
            return $resp
        }
    } while ($next)

    return $items
}

function Get-CaGraphRoot {
    [CmdletBinding()]
    param()
    if ($script:CaState -and
        ($script:CaState.PSObject.Properties.Name -contains 'GraphRoot') -and
        $script:CaState.GraphRoot) {
        return ([string]$script:CaState.GraphRoot).TrimEnd('/')
    }
    return 'https://graph.microsoft.com'
}
