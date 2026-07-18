<#
    Inventory.ps1 - normalized asset inventory across configured providers.

    This is the Cloudlist-style layer: lightweight, stdout/report friendly,
    minimal configuration, and useful as evidence for attack-surface review. It
    reuses the provider CLI contexts already configured for AWS, Azure and GCP.
#>

function Get-CaInventoryFindings {
    [CmdletBinding()]
    param()
    Get-CaFindingsByPrefix -Prefix 'Test-CaInventory*'
}

function Get-CaInventoryMaxAssetsPerProvider {
    $bl = Get-CaBaseline
    if ($bl.PSObject.Properties.Name -contains 'Inventory' -and
        $bl.Inventory.PSObject.Properties.Name -contains 'MaxAssetsPerProvider') {
        return [int]$bl.Inventory.MaxAssetsPerProvider
    }
    return 500
}

function New-CaInventoryAsset {
    param(
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$Type,
        [string]$Name = '',
        [string]$Id = '',
        [string]$Region = '',
        [string]$PublicEndpoint = ''
    )

    [pscustomobject]@{
        Provider       = $Provider
        Type           = $Type
        Name           = $Name
        Id             = $Id
        Region         = $Region
        PublicEndpoint = $PublicEndpoint
    }
}

function Get-CaInventoryAwsAssets {
    param([Parameter(Mandatory)][int]$MaxItems)

    $assets = [System.Collections.Generic.List[object]]::new()
    if (-not (Get-Command -Name 'aws' -ErrorAction SilentlyContinue)) { return @($assets) }

    $buckets = Invoke-CaAwsJson -Arguments @('s3api', 'list-buckets') -AllowFailure
    if ($buckets.Success) {
        foreach ($b in @($buckets.Json.Buckets | Select-Object -First $MaxItems)) {
            $assets.Add((New-CaInventoryAsset -Provider AWS -Type S3Bucket -Name $b.Name -Id $b.Name))
        }
    }

    $regions = @()
    try { $regions = @(Get-CaAwsAuditRegions | Select-Object -First 20) }
    catch { return @($assets) }

    foreach ($region in $regions) {
        if ($assets.Count -ge $MaxItems) { break }
        $ec2 = Invoke-CaAwsJson -Arguments @('ec2', 'describe-instances') -Region $region -AllowFailure
        if ($ec2.Success) {
            foreach ($res in @($ec2.Json.Reservations)) {
                foreach ($inst in @($res.Instances)) {
                    if ($assets.Count -ge $MaxItems) { break }
                    $assets.Add((New-CaInventoryAsset -Provider AWS -Type EC2Instance -Name $inst.InstanceId -Id $inst.InstanceId -Region $region -PublicEndpoint $inst.PublicIpAddress))
                }
            }
        }
        $lambda = Invoke-CaAwsJson -Arguments @('lambda', 'list-functions') -Region $region -AllowFailure
        if ($lambda.Success) {
            foreach ($fn in @($lambda.Json.Functions | Select-Object -First ($MaxItems - $assets.Count))) {
                $assets.Add((New-CaInventoryAsset -Provider AWS -Type LambdaFunction -Name $fn.FunctionName -Id $fn.FunctionArn -Region $region))
            }
        }
    }
    return @($assets)
}

function Get-CaInventoryAzureAssets {
    param([Parameter(Mandatory)][int]$MaxItems)

    $assets = [System.Collections.Generic.List[object]]::new()
    if (-not (Get-Command -Name 'az' -ErrorAction SilentlyContinue)) { return @($assets) }

    $resources = Invoke-CaAzJson -Arguments @('resource', 'list') -AllowFailure
    if ($resources.Success) {
        foreach ($r in @($resources.Json | Select-Object -First $MaxItems)) {
            $assets.Add((New-CaInventoryAsset -Provider Azure -Type $r.type -Name $r.name -Id $r.id -Region $r.location))
        }
    }
    return @($assets)
}

function Get-CaInventoryGcpAssets {
    param([Parameter(Mandatory)][int]$MaxItems)

    $assets = [System.Collections.Generic.List[object]]::new()
    if (-not (Get-Command -Name 'gcloud' -ErrorAction SilentlyContinue)) { return @($assets) }

    $project = Get-CaGcpProject
    $asset = Invoke-CaGcloudJson -Arguments @('asset', 'search-all-resources', '--scope', "projects/$project") -AllowFailure
    if ($asset.Success) {
        foreach ($r in @($asset.Json | Select-Object -First $MaxItems)) {
            $assets.Add((New-CaInventoryAsset -Provider GCP -Type $r.assetType -Name $r.displayName -Id $r.name -Region $r.location))
        }
        return @($assets)
    }

    foreach ($bucket in @(Get-CaGcpBuckets -Project $project | Select-Object -First $MaxItems)) {
        $name = Get-CaGcpBucketName -Bucket $bucket
        $assets.Add((New-CaInventoryAsset -Provider GCP -Type StorageBucket -Name $name -Id $name))
    }
    return @($assets)
}

function Get-CaInventoryTailscaleAssets {
    param([Parameter(Mandatory)][int]$MaxItems)

    $assets = [System.Collections.Generic.List[object]]::new()
    if (Get-CaTailscaleConfigIssue) { return @($assets) }

    foreach ($d in @(Get-CaTailscaleDevices | Select-Object -First $MaxItems)) {
        $assets.Add((New-CaInventoryAsset -Provider Tailscale -Type Device -Name $d.name -Id $d.id -Region $d.os -PublicEndpoint (($d.addresses) -join ',')))
    }
    return @($assets)
}

function Test-CaInventoryAssets {
    Invoke-CaCheck -Service Inventory -CheckId 'INV-001' -Title 'Multi-cloud asset inventory captured' -Body {
        $max = Get-CaInventoryMaxAssetsPerProvider
        $assets = [System.Collections.Generic.List[object]]::new()
        $errors = [System.Collections.Generic.List[string]]::new()

        foreach ($provider in @('AWS', 'Azure', 'GCP', 'Tailscale')) {
            try {
                $items = switch ($provider) {
                    'AWS'       { @(Get-CaInventoryAwsAssets -MaxItems $max) }
                    'Azure'     { @(Get-CaInventoryAzureAssets -MaxItems $max) }
                    'GCP'       { @(Get-CaInventoryGcpAssets -MaxItems $max) }
                    'Tailscale' { @(Get-CaInventoryTailscaleAssets -MaxItems $max) }
                }
                foreach ($item in $items) { $assets.Add($item) }
            }
            catch {
                $errors.Add("${provider}: $($_.Exception.Message)")
            }
        }

        $byProvider = @($assets | Group-Object Provider | ForEach-Object { "$($_.Name)=$($_.Count)" })
        if ($assets.Count -gt 0) {
            $status = if ($errors.Count -gt 0) { 'Warning' } else { 'Info' }
            $severity = if ($errors.Count -gt 0) { 'Low' } else { 'Info' }
            New-CaFinding -Service Inventory -CheckId 'INV-001' -Title 'Multi-cloud asset inventory captured' -Status $status -Severity $severity `
                -Detail "Assets=$($assets.Count); $($byProvider -join '; '); provider errors=$($errors.Count)." `
                -Evidence @{ Assets = @($assets); Errors = @($errors) } `
                -Recommendation 'Use the normalized asset evidence as the starting point for attack-surface review and drift comparisons.'
        }
        elseif ($errors.Count -gt 0) {
            New-CaFinding -Service Inventory -CheckId 'INV-001' -Title 'Multi-cloud asset inventory captured' -Status Warning -Severity Low `
                -Detail "No assets collected; provider errors=$($errors.Count)." -Evidence $errors `
                -Recommendation 'Configure at least one provider CLI/API context before running Inventory.'
        }
        else {
            New-CaFinding -Service Inventory -CheckId 'INV-001' -Title 'Multi-cloud asset inventory captured' -Status Skipped `
                -SkippedReason 'No provider CLI/API context was available.' -Detail 'Install/configure aws, az, gcloud or Tailscale API token.'
        }
    }
}
