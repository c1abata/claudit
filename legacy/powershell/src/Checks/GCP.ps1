<#
    GCP.ps1 - read-only Google Cloud posture checks via gcloud.

    The operator authenticates with gcloud outside Claudit. Project/account/org
    selectors are non-secret runtime options passed by the wizard or runner.
#>

function Get-CaGcpFindings {
    [CmdletBinding()]
    param()
    Get-CaFindingsByPrefix -Prefix 'Test-CaGcp*'
}

function Get-CaGcpBaseArgs {
    $opt = Get-CaProviderOption -Provider GCP
    $args = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($opt.Account)) {
        $args.Add('--account')
        $args.Add($opt.Account)
    }
    return @($args)
}

function Invoke-CaGcloudJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $args = [System.Collections.Generic.List[string]]::new()
    foreach ($a in (Get-CaGcpBaseArgs)) { $args.Add($a) }
    foreach ($a in $Arguments) { $args.Add($a) }
    $args.Add('--format=json')

    Invoke-CaExternalJson -Command 'gcloud' -Arguments @($args) -AllowFailure:$AllowFailure
}

function Invoke-CaGcloudText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $args = [System.Collections.Generic.List[string]]::new()
    foreach ($a in (Get-CaGcpBaseArgs)) { $args.Add($a) }
    foreach ($a in $Arguments) { $args.Add($a) }
    Invoke-CaExternalCommand -Command 'gcloud' -Arguments @($args) -AllowFailure:$AllowFailure
}

function Get-CaGcpProject {
    $opt = Get-CaProviderOption -Provider GCP
    if (-not [string]::IsNullOrWhiteSpace($opt.Project)) { return $opt.Project }
    if (-not [string]::IsNullOrWhiteSpace($env:GOOGLE_CLOUD_PROJECT)) { return $env:GOOGLE_CLOUD_PROJECT }

    $r = Invoke-CaGcloudText -Arguments @('config', 'get-value', 'project') -AllowFailure
    if ($r.Success) {
        $value = $r.Text.Trim()
        if ($value -and $value -ne '(unset)') { return $value }
    }
    throw 'No GCP project selected. Pass -GcpProject or run: gcloud config set project <project-id>.'
}

function Get-CaGcpOrganization {
    $opt = Get-CaProviderOption -Provider GCP
    if (-not [string]::IsNullOrWhiteSpace($opt.Organization)) { return $opt.Organization }
    $bl = Get-CaBaseline
    if ($bl.PSObject.Properties.Name -contains 'GCP' -and $bl.GCP.PSObject.Properties.Name -contains 'Organization') {
        return [string]$bl.GCP.Organization
    }
    return ''
}

function Get-CaGcpBuckets {
    param([Parameter(Mandatory)][string]$Project)
    $r = Invoke-CaGcloudJson -Arguments @('storage', 'buckets', 'list', '--project', $Project) -AllowFailure
    if (-not $r.Success) { throw "Could not list GCS buckets: $($r.Text)" }
    return @($r.Json | Where-Object { $_ })
}

function Get-CaGcpBucketName {
    param([Parameter(Mandatory)]$Bucket)
    $name = [string]$Bucket.name
    if ($name -match '^projects/_/buckets/(.+)$') { return $Matches[1] }
    if ($name -match '^gs://(.+)$') { return $Matches[1] }
    return $name
}

function Test-CaGcpPortSpecificationIncludes {
    param(
        [AllowNull()][string]$Specification,
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port
    )

    if ([string]::IsNullOrWhiteSpace($Specification)) { return $true }
    if ($Specification -match '^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$') {
        $start = [int]$Matches[1]
        $end = [int]$Matches[2]
        return $start -le $Port -and $Port -le $end
    }
    $value = 0
    return [int]::TryParse($Specification.Trim(), [ref]$value) -and $value -eq $Port
}

function Test-CaGcpContext {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-001' -Title 'GCP CLI context resolved' -Body {
        $config = Invoke-CaGcloudJson -Arguments @('config', 'list')
        $project = Get-CaGcpProject
        $account = if ($config.core.account) { $config.core.account } else { '(unset)' }
        New-CaFinding -Service GCP -CheckId 'GCP-001' -Title 'GCP CLI context resolved' -Status Info `
            -Detail "Project=$project; Account=$account." -Evidence $config
    }
}

function Test-CaGcpPrimitiveIamRoles {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-002' -Title 'Primitive IAM roles restricted' -Body {
        $project = Get-CaGcpProject
        $bl = Get-CaBaseline
        $allowed = ConvertTo-CaStringList $bl.GCP.AllowedPrimitiveRoleMembers
        $policy = Invoke-CaGcloudJson -Arguments @('projects', 'get-iam-policy', $project)
        $primitive = @($policy.bindings | Where-Object { $_.role -in @('roles/owner', 'roles/editor') })
        $violations = [System.Collections.Generic.List[string]]::new()
        foreach ($binding in $primitive) {
            foreach ($member in @($binding.members)) {
                if ($allowed -notcontains $member) { $violations.Add("$($binding.role):$member") }
            }
        }

        if ($violations.Count -eq 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-002' -Title 'Primitive IAM roles restricted' -Status Pass `
                -Detail 'No unapproved Owner/Editor primitive role bindings found.' -Evidence $primitive
        }
        else {
            New-CaFinding -Service GCP -CheckId 'GCP-002' -Title 'Primitive IAM roles restricted' -Status Fail -Severity High `
                -Detail "$($violations.Count) unapproved Owner/Editor binding(s)." -Evidence $violations `
                -Recommendation 'Replace primitive Owner/Editor grants with least-privilege predefined or custom roles.' `
                -Reference 'https://cloud.google.com/iam/docs/using-iam-securely'
        }
    }
}

function Test-CaGcpServiceAccountKeys {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-003' -Title 'No stale user-managed service account keys' -Body {
        $project = Get-CaGcpProject
        $bl = Get-CaBaseline
        $maxDays = [int]$bl.GCP.MaxServiceAccountKeyAgeDays
        $cutoff = [DateTime]::UtcNow.AddDays(-$maxDays)
        $accounts = Invoke-CaGcloudJson -Arguments @('iam', 'service-accounts', 'list', '--project', $project)
        $stale = [System.Collections.Generic.List[string]]::new()
        $errors = [System.Collections.Generic.List[string]]::new()

        foreach ($sa in @($accounts)) {
            $email = [string]$sa.email
            if ([string]::IsNullOrWhiteSpace($email)) { continue }
            $keys = Invoke-CaGcloudJson -Arguments @('iam', 'service-accounts', 'keys', 'list', '--iam-account', $email, '--managed-by', 'user', '--project', $project) -AllowFailure
            if (-not $keys.Success) { $errors.Add("${email}: $($keys.Text)"); continue }
            foreach ($key in @($keys.Json)) {
                if ($key.validAfterTime -and ([DateTime]$key.validAfterTime) -lt $cutoff) {
                    $stale.Add("$email/$($key.name)")
                }
            }
        }

        if ($errors.Count -gt 0) {
            throw "Service-account keys could not be completely evaluated: $($errors -join ' | ')"
        }

        if ($stale.Count -eq 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-003' -Title 'No stale user-managed service account keys' -Status Pass `
                -Detail "No user-managed service account keys older than $maxDays day(s)." -Evidence $stale
        }
        else {
            New-CaFinding -Service GCP -CheckId 'GCP-003' -Title 'No stale user-managed service account keys' -Status Fail -Severity Medium `
                -Detail "$($stale.Count) user-managed service account key(s) older than $maxDays day(s)." -Evidence $stale `
                -Recommendation 'Rotate or delete user-managed keys; prefer Workload Identity Federation or attached service accounts.' `
                -Reference 'https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys'
        }
    }
}

function Test-CaGcpDataAccessAuditLogs {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-004' -Title 'Data Access audit logs configured' -Body {
        $project = Get-CaGcpProject
        $bl = Get-CaBaseline
        $required = ConvertTo-CaStringList $bl.GCP.RequiredAuditLogTypes
        $policy = Invoke-CaGcloudJson -Arguments @('projects', 'get-iam-policy', $project)
        $allServices = @($policy.auditConfigs | Where-Object { $_.service -eq 'allServices' })
        $enabled = @($allServices.auditLogConfigs | ForEach-Object { $_.logType } | Sort-Object -Unique)
        $missing = @($required | Where-Object { $enabled -notcontains $_ })

        if ($missing.Count -eq 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-004' -Title 'Data Access audit logs configured' -Status Pass `
                -Detail "Required audit log types enabled: $($required -join ', ')." -Evidence $enabled
        }
        else {
            New-CaFinding -Service GCP -CheckId 'GCP-004' -Title 'Data Access audit logs configured' -Status Fail -Severity Medium `
                -Detail "Missing allServices audit log types: $($missing -join ', ')." -Evidence $enabled `
                -Recommendation 'Enable Data Access audit logging for required services or allServices where policy allows cost impact.' `
                -Reference 'https://cloud.google.com/logging/docs/audit/configure-data-access'
        }
    }
}

function Test-CaGcpPublicBuckets {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-005' -Title 'No public Cloud Storage buckets' -Body {
        $project = Get-CaGcpProject
        $public = [System.Collections.Generic.List[string]]::new()
        $errors = [System.Collections.Generic.List[string]]::new()
        $buckets = @(Get-CaGcpBuckets -Project $project)
        foreach ($bucket in $buckets) {
            $name = Get-CaGcpBucketName -Bucket $bucket
            $policy = Invoke-CaGcloudJson -Arguments @('storage', 'buckets', 'get-iam-policy', "gs://$name") -AllowFailure
            if (-not $policy.Success) { $errors.Add("${name}: $($policy.Text)"); continue }
            foreach ($binding in @($policy.Json.bindings)) {
                if (@($binding.members) -contains 'allUsers' -or @($binding.members) -contains 'allAuthenticatedUsers') {
                    $public.Add("$name/$($binding.role)")
                }
            }
        }

        if ($errors.Count -gt 0) {
            throw "Bucket IAM could not be completely evaluated: $($errors -join ' | ')"
        }

        if ($buckets.Count -eq 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-005' -Title 'No public Cloud Storage buckets' -Status NotApplicable `
                -Detail 'No Cloud Storage bucket exists in the successfully queried project.'
        }
        elseif ($public.Count -eq 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-005' -Title 'No public Cloud Storage buckets' -Status Pass `
                -Detail 'No bucket IAM binding grants allUsers or allAuthenticatedUsers.' -Evidence $public
        }
        else {
            New-CaFinding -Service GCP -CheckId 'GCP-005' -Title 'No public Cloud Storage buckets' -Status Fail -Severity High `
                -Detail "$($public.Count) public bucket binding(s) detected." -Evidence $public `
                -Recommendation 'Remove public bucket IAM grants unless explicitly approved and fronted by public-content controls.' `
                -Reference 'https://cloud.google.com/storage/docs/access-control/making-data-public'
        }
    }
}

function Test-CaGcpUniformBucketAccess {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-006' -Title 'Uniform bucket-level access enabled' -Body {
        $project = Get-CaGcpProject
        $missing = [System.Collections.Generic.List[string]]::new()
        $errors = [System.Collections.Generic.List[string]]::new()
        $buckets = @(Get-CaGcpBuckets -Project $project)
        foreach ($bucket in $buckets) {
            $name = Get-CaGcpBucketName -Bucket $bucket
            $desc = Invoke-CaGcloudJson -Arguments @('storage', 'buckets', 'describe', "gs://$name") -AllowFailure
            if (-not $desc.Success) { $errors.Add("${name}: $($desc.Text)"); continue }
            if (-not [bool]$desc.Json.iamConfiguration.uniformBucketLevelAccess.enabled) {
                $missing.Add($name)
            }
        }

        if ($errors.Count -gt 0) {
            throw "Bucket uniform access could not be completely evaluated: $($errors -join ' | ')"
        }

        if ($buckets.Count -eq 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-006' -Title 'Uniform bucket-level access enabled' -Status NotApplicable `
                -Detail 'No Cloud Storage bucket exists in the successfully queried project.'
        }
        elseif ($missing.Count -eq 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-006' -Title 'Uniform bucket-level access enabled' -Status Pass `
                -Detail 'All discovered buckets use uniform bucket-level access.' -Evidence $missing
        }
        else {
            New-CaFinding -Service GCP -CheckId 'GCP-006' -Title 'Uniform bucket-level access enabled' -Status Fail -Severity Medium `
                -Detail "Buckets without uniform access: $($missing -join ', ')." -Evidence $missing `
                -Recommendation 'Enable uniform bucket-level access to remove object ACL drift.' `
                -Reference 'https://cloud.google.com/storage/docs/uniform-bucket-level-access'
        }
    }
}

function Test-CaGcpDefaultNetwork {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-007' -Title 'Default VPC network absent' -Body {
        $project = Get-CaGcpProject
        $r = Invoke-CaGcloudJson -Arguments @('compute', 'networks', 'list', '--project', $project) -AllowFailure
        if (-not $r.Success) {
            return New-CaFinding -Service GCP -CheckId 'GCP-007' -Title 'Default VPC network absent' -Status Skipped `
                -SkippedReason 'Compute API disabled or inaccessible.' -Detail $r.Text
        }
        $default = @($r.Json | Where-Object { $_.name -eq 'default' })
        if ($default.Count -eq 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-007' -Title 'Default VPC network absent' -Status Pass -Detail 'No default VPC network found.' -Evidence $default
        }
        else {
            New-CaFinding -Service GCP -CheckId 'GCP-007' -Title 'Default VPC network absent' -Status Fail -Severity Medium `
                -Detail 'Default VPC network exists.' -Evidence $default `
                -Recommendation 'Delete default networks and create explicit VPCs with reviewed firewall rules.' `
                -Reference 'https://cloud.google.com/vpc/docs/vpc'
        }
    }
}

function Test-CaGcpOpenAdminFirewall {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-008' -Title 'No firewall rules expose admin ports to the internet' -Body {
        $project = Get-CaGcpProject
        $r = Invoke-CaGcloudJson -Arguments @('compute', 'firewall-rules', 'list', '--project', $project) -AllowFailure
        if (-not $r.Success) {
            return New-CaFinding -Service GCP -CheckId 'GCP-008' -Title 'No firewall rules expose admin ports to the internet' -Status Skipped `
                -SkippedReason 'Compute API disabled or inaccessible.' -Detail $r.Text
        }

        $bad = [System.Collections.Generic.List[string]]::new()
        foreach ($rule in @($r.Json)) {
            if ([bool]$rule.disabled -or $rule.direction -eq 'EGRESS') { continue }
            $openSource = @($rule.sourceRanges) | Where-Object { $_ -in @('0.0.0.0/0', '::/0') }
            if (-not $openSource) { continue }
            foreach ($allow in @($rule.allowed)) {
                $proto = [string]$allow.IPProtocol
                $ports = @($allow.ports)
                $adminPort = @($ports | Where-Object {
                    (Test-CaGcpPortSpecificationIncludes -Specification ([string]$_) -Port 22) -or
                    (Test-CaGcpPortSpecificationIncludes -Specification ([string]$_) -Port 3389)
                }).Count -gt 0
                if ($proto -eq 'all' -or ($proto -eq 'tcp' -and ($ports.Count -eq 0 -or $adminPort))) {
                    $bad.Add($rule.name)
                }
            }
        }
        $bad = @($bad | Sort-Object -Unique)

        if ($bad.Count -eq 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-008' -Title 'No firewall rules expose admin ports to the internet' -Status Pass `
                -Detail 'No ingress firewall rule exposes SSH/RDP/all protocols to 0.0.0.0/0 or ::/0.' -Evidence $bad
        }
        else {
            New-CaFinding -Service GCP -CheckId 'GCP-008' -Title 'No firewall rules expose admin ports to the internet' -Status Fail -Severity High `
                -Detail "Internet-exposed admin firewall rules: $($bad -join ', ')." -Evidence $bad `
                -Recommendation 'Restrict SSH/RDP to trusted ranges or use IAP/OS Login/Bastion patterns.' `
                -Reference 'https://cloud.google.com/vpc/docs/firewalls'
        }
    }
}

function Test-CaGcpOsLogin {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-009' -Title 'OS Login enabled at project level' -Body {
        $project = Get-CaGcpProject
        $bl = Get-CaBaseline
        if ($bl.GCP.PSObject.Properties.Name -contains 'RequireOsLogin' -and -not [bool]$bl.GCP.RequireOsLogin) {
            return New-CaFinding -Service GCP -CheckId 'GCP-009' -Title 'OS Login enabled at project level' -Status Info -Detail 'Baseline does not require this control.'
        }

        $r = Invoke-CaGcloudJson -Arguments @('compute', 'project-info', 'describe', '--project', $project) -AllowFailure
        if (-not $r.Success) {
            return New-CaFinding -Service GCP -CheckId 'GCP-009' -Title 'OS Login enabled at project level' -Status Skipped `
                -SkippedReason 'Compute API disabled or inaccessible.' -Detail $r.Text
        }
        $item = @($r.Json.commonInstanceMetadata.items | Where-Object { $_.key -eq 'enable-oslogin' } | Select-Object -First 1)
        $enabled = $item.Count -gt 0 -and [string]$item[0].value -match '^(TRUE|true|1)$'
        if ($enabled) {
            New-CaFinding -Service GCP -CheckId 'GCP-009' -Title 'OS Login enabled at project level' -Status Pass -Detail 'enable-oslogin metadata is true.' -Evidence $item
        }
        else {
            New-CaFinding -Service GCP -CheckId 'GCP-009' -Title 'OS Login enabled at project level' -Status Fail -Severity Medium `
                -Detail 'Project metadata does not enable OS Login.' -Evidence $item `
                -Recommendation 'Enable OS Login and bind SSH access through IAM instead of project-wide SSH keys.' `
                -Reference 'https://cloud.google.com/compute/docs/oslogin'
        }
    }
}

function Test-CaGcpLoggingSinks {
    Invoke-CaCheck -Service GCP -CheckId 'GCP-010' -Title 'Project logging sink configured' -Body {
        $project = Get-CaGcpProject
        $bl = Get-CaBaseline
        $require = if ($bl.GCP.PSObject.Properties.Name -contains 'RequireCentralLogSink') { [bool]$bl.GCP.RequireCentralLogSink } else { $true }
        $r = Invoke-CaGcloudJson -Arguments @('logging', 'sinks', 'list', '--project', $project) -AllowFailure
        if (-not $r.Success) { throw $r.Text }
        $allSinks = @($r.Json | Where-Object { $_ })
        $systemSinks = @($allSinks | Where-Object { [string]$_.name -in @('_Required', '_Default') })
        $centralSinks = @($allSinks | Where-Object {
            $name = [string]$_.name
            $destination = [string]$_.destination
            $disabled = ($_.PSObject.Properties.Name -contains 'disabled') -and [bool]$_.disabled
            $localBucketPrefix = "logging.googleapis.com/projects/$project/locations/"
            $name -notin @('_Required', '_Default') -and -not $disabled -and
                -not [string]::IsNullOrWhiteSpace($destination) -and
                -not $destination.StartsWith($localBucketPrefix, [System.StringComparison]::OrdinalIgnoreCase)
        })

        if ($centralSinks.Count -gt 0) {
            New-CaFinding -Service GCP -CheckId 'GCP-010' -Title 'Project logging sink configured' -Status Pass `
                -Detail "$($centralSinks.Count) enabled user-defined export/central sink(s) configured; ignored $($systemSinks.Count) system sink(s)." `
                -Evidence @{ CentralSinks=$centralSinks; SystemSinks=$systemSinks }
        }
        elseif ($require) {
            New-CaFinding -Service GCP -CheckId 'GCP-010' -Title 'Project logging sink configured' -Status Fail -Severity Low `
                -Detail "No enabled user-defined export/central sink configured; $($systemSinks.Count) system sink(s) do not satisfy the baseline." `
                -Recommendation 'Create sinks for central SIEM/storage retention where organization policy requires it.' `
                -Reference 'https://cloud.google.com/logging/docs/export/configure_export_v2'
        }
        else {
            New-CaFinding -Service GCP -CheckId 'GCP-010' -Title 'Project logging sink configured' -Status Info -Detail 'No sink configured; baseline does not require one.'
        }
    }
}
