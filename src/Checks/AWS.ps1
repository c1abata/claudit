<#
    AWS.ps1 - read-only AWS account posture checks via the official aws CLI.

    The checks use list/describe/get APIs only. CLI credentials and profiles stay
    in the operator workstation configuration; Claudit never stores AWS secrets.
#>

function Get-CaAwsFindings {
    [CmdletBinding()]
    param()
    Get-CaFindingsByPrefix -Prefix 'Test-CaAws*'
}

function Get-CaAwsBaseArgs {
    $opt = Get-CaProviderOption -Provider AWS
    $args = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($opt.Profile)) {
        $args.Add('--profile')
        $args.Add($opt.Profile)
    }
    return @($args)
}

function Invoke-CaAwsJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$Region = '',
        [switch]$AllowFailure
    )

    $args = [System.Collections.Generic.List[string]]::new()
    foreach ($a in (Get-CaAwsBaseArgs)) { $args.Add($a) }
    foreach ($a in $Arguments) { $args.Add($a) }
    if (-not [string]::IsNullOrWhiteSpace($Region)) {
        $args.Add('--region')
        $args.Add($Region)
    }
    $args.Add('--output')
    $args.Add('json')

    Invoke-CaExternalJson -Command 'aws' -Arguments @($args) -AllowFailure:$AllowFailure
}

$script:CaAwsIdentityCache = @{}

function Get-CaAwsCallerIdentity {
    $cacheKey = (Get-CaAwsBaseArgs) -join "`u{001f}"
    if ($script:CaAwsIdentityCache.ContainsKey($cacheKey)) { return $script:CaAwsIdentityCache[$cacheKey] }
    $identity = Invoke-CaAwsJson -Arguments @('sts', 'get-caller-identity')
    $script:CaAwsIdentityCache[$cacheKey] = $identity
    return $identity
}

function Get-CaAwsAuditRegions {
    $opt = Get-CaProviderOption -Provider AWS
    $regions = ConvertTo-CaStringList $opt.Regions
    if ($regions.Count -gt 0) { return $regions }

    $bl = Get-CaBaseline
    if ($bl.PSObject.Properties.Name -contains 'AWS') {
        $regions = ConvertTo-CaStringList $bl.AWS.Regions
        if ($regions.Count -gt 0) { return $regions }
    }

    $json = Invoke-CaAwsJson -Arguments @('ec2', 'describe-regions', '--all-regions', '--query', 'Regions[].RegionName') -Region 'us-east-1'
    return @(ConvertTo-CaStringList $json)
}

function Test-CaAwsCallerIdentity {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-001' -Title 'AWS caller identity resolved' -Body {
        $id = Get-CaAwsCallerIdentity
        New-CaFinding -Service AWS -CheckId 'AWS-001' -Title 'AWS caller identity resolved' -Status Info `
            -Detail "Account=$($id.Account); Arn=$($id.Arn)." -Evidence $id
    }
}

function Test-CaAwsRootMfa {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-002' -Title 'Root account MFA enabled' -Body {
        $summary = Invoke-CaAwsJson -Arguments @('iam', 'get-account-summary')
        $enabled = [int]$summary.SummaryMap.AccountMFAEnabled
        if ($enabled -eq 1) {
            New-CaFinding -Service AWS -CheckId 'AWS-002' -Title 'Root account MFA enabled' -Status Pass -Detail 'AccountMFAEnabled = 1.' -Evidence $enabled
        }
        else {
            New-CaFinding -Service AWS -CheckId 'AWS-002' -Title 'Root account MFA enabled' -Status Fail -Severity Critical `
                -Detail 'The AWS root account does not have MFA enabled.' -Evidence $enabled `
                -Recommendation 'Enable hardware/FIDO2 MFA on the root user and avoid routine root use.' `
                -Reference 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html'
        }
    }
}

function Get-CaAwsVpcFlowLogSnapshot {
    [CmdletBinding()]
    param()

    $missing = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $queriedVpcs = 0
    $regions = @(Get-CaAwsAuditRegions)

    foreach ($region in $regions) {
        $vpcsDoc = Invoke-CaAwsJson -Arguments @('ec2', 'describe-vpcs') -Region $region -AllowFailure
        if (-not $vpcsDoc.Success) { $errors.Add("${region}/vpcs: $($vpcsDoc.Text)"); continue }
        if ($null -eq $vpcsDoc.Json -or $vpcsDoc.Json.PSObject.Properties.Name -notcontains 'Vpcs') {
            $errors.Add("${region}/vpcs: invalid data returned by describe-vpcs")
            continue
        }

        $vpcs = @($vpcsDoc.Json.Vpcs | Where-Object { $_ })
        $queriedVpcs += $vpcs.Count
        if ($vpcs.Count -eq 0) { continue }
        $ids = @($vpcs | ForEach-Object { [string]$_.VpcId } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($ids.Count -ne $vpcs.Count) {
            $errors.Add("${region}/vpcs: invalid data contains a VPC without VpcId")
            continue
        }

        $filter = 'Name=resource-id,Values=' + ($ids -join ',')
        $logsDoc = Invoke-CaAwsJson -Arguments @('ec2', 'describe-flow-logs', '--filter', $filter) -Region $region -AllowFailure
        if (-not $logsDoc.Success) { $errors.Add("${region}/flow-logs: $($logsDoc.Text)"); continue }
        if ($null -eq $logsDoc.Json -or $logsDoc.Json.PSObject.Properties.Name -notcontains 'FlowLogs') {
            $errors.Add("${region}/flow-logs: invalid data returned by describe-flow-logs")
            continue
        }

        $logged = @($logsDoc.Json.FlowLogs | ForEach-Object { [string]$_.ResourceId } | Where-Object { $_ } | Sort-Object -Unique)
        foreach ($vpcId in $ids) {
            if ($logged -notcontains $vpcId) { $missing.Add("$region/$vpcId") }
        }
    }

    [pscustomobject]@{
        Regions      = @($regions)
        QueriedVpcs  = $queriedVpcs
        Missing      = @($missing | Sort-Object -Unique)
        Errors       = @($errors)
    }
}

function Test-CaAwsVpcFlowLogSnapshot {
    [CmdletBinding()]
    param([AllowNull()]$Snapshot)

    $required = @('Regions', 'QueriedVpcs', 'Missing', 'Errors')
    $missingFields = @(if ($null -eq $Snapshot) { $required } else { $required | Where-Object { $_ -notin $Snapshot.PSObject.Properties.Name } })
    if ($missingFields.Count -gt 0) {
        return New-CaCheckAssessment -Status Error -Severity Medium -FailureCategory Data `
            -FailureCode 'AwsVpcFlowLogSnapshotInvalid' `
            -Detail "Invalid VPC Flow Logs snapshot; missing fields: $($missingFields -join ', ')." -Evidence $Snapshot
    }

    $queriedVpcs = 0
    if (-not [int]::TryParse([string]$Snapshot.QueriedVpcs, [ref]$queriedVpcs) -or $queriedVpcs -lt 0) {
        return New-CaCheckAssessment -Status Error -Severity Medium -FailureCategory Data `
            -FailureCode 'AwsVpcFlowLogSnapshotInvalid' `
            -Detail 'Invalid VPC Flow Logs snapshot; QueriedVpcs must be a non-negative integer.' -Evidence $Snapshot
    }

    $regions = @(ConvertTo-CaStringList $Snapshot.Regions)
    $missing = @(ConvertTo-CaStringList $Snapshot.Missing | Sort-Object -Unique)
    $errors = @(ConvertTo-CaStringList $Snapshot.Errors)
    $evidence = [pscustomobject]@{ Regions=$regions; QueriedVpcs=$queriedVpcs; Missing=$missing; Errors=$errors }

    if ($regions.Count -eq 0) {
        return New-CaCheckAssessment -Status Error -Severity Medium -FailureCategory Prerequisite `
            -FailureCode 'AwsAuditRegionMissing' -Detail 'No AWS audit region was resolved.' -Evidence $evidence
    }
    if ($errors.Count -gt 0) {
        $detail = "VPC Flow Logs could not be completely evaluated: $($errors -join ' | ')"
        $category = Get-CaFailureCategory -ErrorRecord ([System.InvalidOperationException]::new($detail))
        return New-CaCheckAssessment -Status Error -Severity Medium -FailureCategory $category `
            -FailureCode 'AwsVpcFlowLogsCollectionFailed' -Detail $detail -Evidence $evidence
    }
    if ($missing.Count -gt $queriedVpcs) {
        return New-CaCheckAssessment -Status Error -Severity Medium -FailureCategory Data `
            -FailureCode 'AwsVpcFlowLogSnapshotInvalid' `
            -Detail 'Invalid VPC Flow Logs snapshot; missing VPC count exceeds queried VPC count.' -Evidence $evidence
    }
    if ($queriedVpcs -eq 0) {
        return New-CaCheckAssessment -Status NotApplicable `
            -Detail "No VPC exists in the $($regions.Count) successfully queried audit region(s)." -Evidence $evidence
    }
    if ($missing.Count -eq 0) {
        return New-CaCheckAssessment -Status Pass `
            -Detail "All $queriedVpcs discovered VPC(s) have flow logs." -Evidence $evidence
    }

    New-CaCheckAssessment -Status Fail -Severity Medium `
        -Detail "$($missing.Count) VPC(s) without flow logs." -Evidence $evidence `
        -Recommendation 'Enable VPC Flow Logs to CloudWatch Logs or S3 for every production VPC.' `
        -Reference 'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
}

function Test-CaAwsPasswordPolicy {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-003' -Title 'IAM account password policy meets baseline' -Body {
        $bl = Get-CaBaseline
        $result = Invoke-CaAwsJson -Arguments @('iam', 'get-account-password-policy') -AllowFailure
        if (-not $result.Success) {
            if ($result.Text -match 'NoSuchEntity|not exist|cannot be found') {
                return New-CaFinding -Service AWS -CheckId 'AWS-003' -Title 'IAM account password policy meets baseline' -Status Fail -Severity High `
                    -Detail 'No IAM account password policy is configured.' `
                    -Recommendation 'Configure an account password policy or move human access to IAM Identity Center.'
            }
            throw $result.Text
        }

        $p = $result.Json.PasswordPolicy
        $minLength = [int]$bl.AWS.MinPasswordLength
        $maxAge = [int]$bl.AWS.MaxPasswordAgeDays
        $reuse = [int]$bl.AWS.PasswordReusePrevention
        $problems = [System.Collections.Generic.List[string]]::new()
        if ([int]$p.MinimumPasswordLength -lt $minLength) { $problems.Add("MinimumPasswordLength=$($p.MinimumPasswordLength) < $minLength") }
        if (-not [bool]$p.RequireUppercaseCharacters) { $problems.Add('uppercase not required') }
        if (-not [bool]$p.RequireLowercaseCharacters) { $problems.Add('lowercase not required') }
        if (-not [bool]$p.RequireNumbers) { $problems.Add('numbers not required') }
        if (-not [bool]$p.RequireSymbols) { $problems.Add('symbols not required') }
        if ([int]$p.MaxPasswordAge -gt $maxAge) { $problems.Add("MaxPasswordAge=$($p.MaxPasswordAge) > $maxAge") }
        if ([int]$p.PasswordReusePrevention -lt $reuse) { $problems.Add("PasswordReusePrevention=$($p.PasswordReusePrevention) < $reuse") }

        if ($problems.Count -eq 0) {
            New-CaFinding -Service AWS -CheckId 'AWS-003' -Title 'IAM account password policy meets baseline' -Status Pass `
                -Detail "Password policy meets baseline: length >= $minLength, age <= $maxAge, reuse >= $reuse." -Evidence $p
        }
        else {
            New-CaFinding -Service AWS -CheckId 'AWS-003' -Title 'IAM account password policy meets baseline' -Status Fail -Severity Medium `
                -Detail ($problems -join '; ') -Evidence $p `
                -Recommendation 'Harden IAM password policy or remove IAM users in favor of federated access.' `
                -Reference 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html'
        }
    }
}

function Test-CaAwsCloudTrail {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-004' -Title 'CloudTrail multi-region logging enabled' -Body {
        $regions = @(Get-CaAwsAuditRegions)
        $homeRegion = $regions | Select-Object -First 1
        $trailsDoc = Invoke-CaAwsJson -Arguments @('cloudtrail', 'describe-trails', '--include-shadow-trails') -Region $homeRegion
        $multi = @($trailsDoc.trailList | Where-Object { $_.IsMultiRegionTrail })
        $logging = [System.Collections.Generic.List[string]]::new()
        $notLogging = [System.Collections.Generic.List[string]]::new()

        foreach ($trail in $multi) {
            $region = if ($trail.HomeRegion) { $trail.HomeRegion } else { $homeRegion }
            $status = Invoke-CaAwsJson -Arguments @('cloudtrail', 'get-trail-status', '--name', $trail.TrailARN) -Region $region
            if ($status.IsLogging) { $logging.Add($trail.Name) } else { $notLogging.Add($trail.Name) }
        }

        if ($logging.Count -gt 0 -and $notLogging.Count -eq 0) {
            New-CaFinding -Service AWS -CheckId 'AWS-004' -Title 'CloudTrail multi-region logging enabled' -Status Pass `
                -Detail "Multi-region CloudTrail logging active: $($logging -join ', ')." -Evidence $multi
        }
        else {
            $detail = if ($multi.Count -eq 0) { 'No multi-region CloudTrail trail found.' } else { "Not logging: $($notLogging -join ', ')." }
            New-CaFinding -Service AWS -CheckId 'AWS-004' -Title 'CloudTrail multi-region logging enabled' -Status Fail -Severity High `
                -Detail $detail -Evidence $multi `
                -Recommendation 'Create an organization or account multi-region trail with log file validation and protected S3 delivery.' `
                -Reference 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html'
        }
    }
}

function Test-CaAwsGuardDuty {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-005' -Title 'GuardDuty detectors enabled in audit regions' -Body {
        $regions = @(Get-CaAwsAuditRegions)
        $missing = [System.Collections.Generic.List[string]]::new()
        $errors = [System.Collections.Generic.List[string]]::new()
        foreach ($region in $regions) {
            $r = Invoke-CaAwsJson -Arguments @('guardduty', 'list-detectors') -Region $region -AllowFailure
            if (-not $r.Success) { $errors.Add("${region}: $($r.Text)"); continue }
            $detectorIds = @($r.Json.DetectorIds | Where-Object { $_ })
            if ($detectorIds.Count -eq 0) { $missing.Add($region); continue }

            $enabled = $false
            foreach ($detectorId in $detectorIds) {
                $detector = Invoke-CaAwsJson -Arguments @('guardduty', 'get-detector', '--detector-id', [string]$detectorId) -Region $region -AllowFailure
                if (-not $detector.Success) {
                    $errors.Add("${region}/${detectorId}: $($detector.Text)")
                    continue
                }
                if ([string]$detector.Json.Status -eq 'ENABLED') { $enabled = $true }
            }
            if (-not $enabled) { $missing.Add($region) }
        }

        if ($errors.Count -gt 0) {
            throw "GuardDuty could not be completely evaluated: $($errors -join ' | ')"
        }
        if ($missing.Count -eq 0) {
            New-CaFinding -Service AWS -CheckId 'AWS-005' -Title 'GuardDuty detectors enabled in audit regions' -Status Pass `
                -Detail "GuardDuty enabled in $($regions.Count) region(s)." -Evidence $regions
        }
        else {
            New-CaFinding -Service AWS -CheckId 'AWS-005' -Title 'GuardDuty detectors enabled in audit regions' -Status Fail -Severity High `
                -Detail "No enabled GuardDuty detector in: $($missing -join ', ')." -Evidence $missing `
                -Recommendation 'Enable GuardDuty in every active region and delegate administration through AWS Organizations where possible.' `
                -Reference 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html'
        }
    }
}

function Test-CaAwsSecurityHub {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-006' -Title 'Security Hub enabled in audit regions' -Body {
        $regions = @(Get-CaAwsAuditRegions)
        $missing = [System.Collections.Generic.List[string]]::new()
        foreach ($region in $regions) {
            $r = Invoke-CaAwsJson -Arguments @('securityhub', 'describe-hub') -Region $region -AllowFailure
            if (-not $r.Success) { $missing.Add($region) }
        }

        if ($missing.Count -eq 0) {
            New-CaFinding -Service AWS -CheckId 'AWS-006' -Title 'Security Hub enabled in audit regions' -Status Pass `
                -Detail "Security Hub enabled in $($regions.Count) region(s)." -Evidence $regions
        }
        else {
            New-CaFinding -Service AWS -CheckId 'AWS-006' -Title 'Security Hub enabled in audit regions' -Status Fail -Severity Medium `
                -Detail "Security Hub disabled or inaccessible in: $($missing -join ', ')." -Evidence $missing `
                -Recommendation 'Enable Security Hub standards in active regions and aggregate findings centrally.' `
                -Reference 'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-settingup.html'
        }
    }
}

function Test-CaAwsS3AccountPublicAccessBlock {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-007' -Title 'S3 account-level public access block enabled' -Body {
        $accountId = (Get-CaAwsCallerIdentity).Account
        $r = Invoke-CaAwsJson -Arguments @('s3control', 'get-public-access-block', '--account-id', $accountId) -AllowFailure
        if (-not $r.Success) {
            throw "Could not read S3 account public access block: $($r.Text)"
        }

        $c = $r.Json.PublicAccessBlockConfiguration
        $required = @('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')
        $missing = @($required | Where-Object { -not [bool]$c.$_ })
        if ($missing.Count -eq 0) {
            New-CaFinding -Service AWS -CheckId 'AWS-007' -Title 'S3 account-level public access block enabled' -Status Pass `
                -Detail 'All account-level S3 public access block flags are enabled.' -Evidence $c
        }
        else {
            New-CaFinding -Service AWS -CheckId 'AWS-007' -Title 'S3 account-level public access block enabled' -Status Fail -Severity High `
                -Detail "Disabled flags: $($missing -join ', ')." -Evidence $c `
                -Recommendation 'Enable all four S3 Block Public Access flags at account level.' `
                -Reference 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html'
        }
    }
}

function Test-CaAwsStaleAccessKeys {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-008' -Title 'No active IAM access keys older than baseline' -Body {
        $bl = Get-CaBaseline
        $maxDays = [int]$bl.AWS.MaxAccessKeyAgeDays
        $cutoff = [DateTime]::UtcNow.AddDays(-$maxDays)
        $users = Invoke-CaAwsJson -Arguments @('iam', 'list-users')
        $stale = [System.Collections.Generic.List[string]]::new()

        foreach ($user in @($users.Users | Where-Object { $_ })) {
            $keys = Invoke-CaAwsJson -Arguments @('iam', 'list-access-keys', '--user-name', $user.UserName)
            foreach ($key in @($keys.AccessKeyMetadata)) {
                if ($key.Status -eq 'Active' -and ([DateTime]$key.CreateDate) -lt $cutoff) {
                    $stale.Add("$($user.UserName)/$($key.AccessKeyId)")
                }
            }
        }

        if ($stale.Count -eq 0) {
            New-CaFinding -Service AWS -CheckId 'AWS-008' -Title 'No active IAM access keys older than baseline' -Status Pass `
                -Detail "No active access keys older than $maxDays day(s)." -Evidence $stale
        }
        else {
            New-CaFinding -Service AWS -CheckId 'AWS-008' -Title 'No active IAM access keys older than baseline' -Status Fail -Severity Medium `
                -Detail "$($stale.Count) active access key(s) older than $maxDays day(s)." -Evidence $stale `
                -Recommendation 'Rotate or remove long-lived IAM user keys; prefer federation/roles and short-lived credentials.' `
                -Reference 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html'
        }
    }
}

function Test-CaAwsEbsDefaultEncryption {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-009' -Title 'EBS encryption by default enabled in audit regions' -Body {
        $regions = @(Get-CaAwsAuditRegions)
        $missing = [System.Collections.Generic.List[string]]::new()
        $errors = [System.Collections.Generic.List[string]]::new()
        foreach ($region in $regions) {
            $r = Invoke-CaAwsJson -Arguments @('ec2', 'get-ebs-encryption-by-default') -Region $region -AllowFailure
            if (-not $r.Success) { $errors.Add("${region}: $($r.Text)"); continue }
            if (-not [bool]$r.Json.EbsEncryptionByDefault) { $missing.Add($region) }
        }

        if ($errors.Count -gt 0) {
            throw "EBS encryption could not be completely evaluated: $($errors -join ' | ')"
        }

        if ($missing.Count -eq 0) {
            New-CaFinding -Service AWS -CheckId 'AWS-009' -Title 'EBS encryption by default enabled in audit regions' -Status Pass `
                -Detail "EBS default encryption enabled in $($regions.Count) region(s)." -Evidence $regions
        }
        else {
            New-CaFinding -Service AWS -CheckId 'AWS-009' -Title 'EBS encryption by default enabled in audit regions' -Status Fail -Severity Medium `
                -Detail "Disabled: $($missing -join ', '); errors: $($errors.Count)." -Evidence @{ Missing = $missing; Errors = $errors } `
                -Recommendation 'Enable EBS encryption by default in every active region.' `
                -Reference 'https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html'
        }
    }
}

function Test-CaAwsConfigRecorders {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-010' -Title 'AWS Config recorders active in audit regions' -Body {
        $regions = @(Get-CaAwsAuditRegions)
        $missing = [System.Collections.Generic.List[string]]::new()
        $errors = [System.Collections.Generic.List[string]]::new()
        foreach ($region in $regions) {
            $r = Invoke-CaAwsJson -Arguments @('configservice', 'describe-configuration-recorder-status') -Region $region -AllowFailure
            if (-not $r.Success) {
                $errors.Add("${region}: $($r.Text)")
                continue
            }
            if (@($r.Json.ConfigurationRecordersStatus | Where-Object { $_.Recording }).Count -eq 0) {
                $missing.Add($region)
            }
        }

        if ($errors.Count -gt 0) {
            throw "AWS Config could not be completely evaluated: $($errors -join ' | ')"
        }

        if ($missing.Count -eq 0) {
            New-CaFinding -Service AWS -CheckId 'AWS-010' -Title 'AWS Config recorders active in audit regions' -Status Pass `
                -Detail "AWS Config recording in $($regions.Count) region(s)." -Evidence $regions
        }
        else {
            New-CaFinding -Service AWS -CheckId 'AWS-010' -Title 'AWS Config recorders active in audit regions' -Status Fail -Severity Medium `
                -Detail "No active recorder in: $($missing -join ', ')." -Evidence $missing `
                -Recommendation 'Enable AWS Config recording in all active regions and aggregate configuration history centrally.' `
                -Reference 'https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html'
        }
    }
}

function Test-CaAwsVpcFlowLogs {
    Invoke-CaCheck -Service AWS -CheckId 'AWS-011' -Title 'VPC flow logs enabled for all VPCs in audit regions' -Body {
        $bl = Get-CaBaseline
        if ($bl.AWS.PSObject.Properties.Name -contains 'RequireVpcFlowLogs' -and -not [bool]$bl.AWS.RequireVpcFlowLogs) {
            $assessment = New-CaCheckAssessment -Status NotApplicable -Detail 'Baseline does not require this control.'
            return $assessment | ConvertTo-CaFinding -Service AWS -CheckId 'AWS-011' -Title 'VPC flow logs enabled for all VPCs in audit regions'
        }

        $assessment = Test-CaAwsVpcFlowLogSnapshot -Snapshot (Get-CaAwsVpcFlowLogSnapshot)
        $assessment | ConvertTo-CaFinding -Service AWS -CheckId 'AWS-011' -Title 'VPC flow logs enabled for all VPCs in audit regions'
    }
}
