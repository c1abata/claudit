BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\Claudit.psd1') -Force
}

Describe 'Claudit AWS provider regressions' {
    InModuleScope Claudit {
        BeforeEach {
            Mock Get-CaAwsAuditRegions { @('eu-west-1') }
            Mock Get-CaBaseline { [pscustomobject]@{ AWS = [pscustomobject]@{ RequireVpcFlowLogs = $true } } }
        }

        It 'returns an execution error when VPC discovery is denied' {
            Mock Invoke-CaAwsJson {
                [pscustomobject]@{ Success=$false; State='Denied'; Text='AccessDenied'; Error='AccessDenied'; Json=$null }
            }

            $finding = Test-CaAwsVpcFlowLogs

            $finding.Status | Should -Be 'Error'
            $finding.FailureCategory | Should -Be 'Authorization'
        }

        It 'does not treat a disabled GuardDuty detector ID as enabled' {
            Mock Invoke-CaAwsJson {
                if ($Arguments -contains 'list-detectors') {
                    return [pscustomobject]@{ Success=$true; State='Ok'; Text=''; Json=[pscustomobject]@{ DetectorIds=@('detector-1') } }
                }
                [pscustomobject]@{ Success=$true; State='Ok'; Text=''; Json=[pscustomobject]@{ Status='DISABLED' } }
            }

            (Test-CaAwsGuardDuty).Status | Should -Be 'Fail'
        }

        It 'marks a successfully queried account with no VPC as not applicable' {
            Mock Invoke-CaAwsJson {
                [pscustomobject]@{ Success=$true; State='Ok'; Text=''; Json=[pscustomobject]@{ Vpcs=@() } }
            }

            (Test-CaAwsVpcFlowLogs).Status | Should -Be 'NotApplicable'
        }

        It 'does not query AWS when the baseline excludes VPC Flow Logs' {
            Mock Get-CaBaseline { [pscustomobject]@{ AWS = [pscustomobject]@{ RequireVpcFlowLogs = $false } } }
            Mock Invoke-CaAwsJson { throw 'must not query provider' }

            (Test-CaAwsVpcFlowLogs).Status | Should -Be 'NotApplicable'
            Should -Invoke Invoke-CaAwsJson -Times 0
        }

        It 'evaluates PASS, FAIL, no-resource and provider-error fixtures offline' {
            $moduleRoot = Split-Path -Parent (Get-Module Claudit).Path
            $fixturePath = Join-Path $moduleRoot 'tests\fixtures\providers\aws\vpc-flow-logs.json'
            $fixtureCases = @((Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json).Cases)
            foreach ($case in $fixtureCases) {
                $assessment = Test-CaAwsVpcFlowLogSnapshot -Snapshot $case.Snapshot
                $assessment.Status | Should -Be $case.ExpectedStatus -Because $case.Name
                $assessment.FailureCategory | Should -Be $case.ExpectedFailureCategory -Because $case.Name
            }
        }

        It 'classifies malformed provider data as an adapter error' {
            $assessment = Test-CaAwsVpcFlowLogSnapshot -Snapshot ([pscustomobject]@{ Regions=@('eu-west-1') })

            $assessment.Status | Should -Be 'Error'
            $assessment.FailureCategory | Should -Be 'Data'
            $assessment.FailureCode | Should -Be 'AwsVpcFlowLogSnapshotInvalid'
        }
    }
}

Describe 'Claudit GCP provider regressions' {
    InModuleScope Claudit {
        BeforeEach { Mock Get-CaGcpProject { 'fixture-project' } }

        It 'detects SSH inside a firewall port range' {
            Mock Invoke-CaGcloudJson {
                [pscustomobject]@{
                    Success=$true; State='Ok'; Text=''
                    Json=@([pscustomobject]@{
                        name='wide-ssh'; disabled=$false; direction='INGRESS'
                        sourceRanges=@('0.0.0.0/0')
                        allowed=@([pscustomobject]@{ IPProtocol='tcp'; ports=@('20-30') })
                    })
                }
            }

            (Test-CaGcpOpenAdminFirewall).Status | Should -Be 'Fail'
        }

        It 'does not count system logging sinks as central export' {
            Mock Get-CaBaseline { [pscustomobject]@{ GCP=[pscustomobject]@{ RequireCentralLogSink=$true } } }
            Mock Invoke-CaGcloudJson {
                [pscustomobject]@{
                    Success=$true; State='Ok'; Text=''
                    Json=@(
                        [pscustomobject]@{ name='_Required'; destination='logging.googleapis.com/projects/fixture-project/locations/global/buckets/_Required'; disabled=$false },
                        [pscustomobject]@{ name='_Default'; destination='logging.googleapis.com/projects/fixture-project/locations/global/buckets/_Default'; disabled=$false }
                    )
                }
            }

            (Test-CaGcpLoggingSinks).Status | Should -Be 'Fail'
        }

        It 'fails closed when bucket IAM cannot be read' {
            Mock Get-CaGcpBuckets { @([pscustomobject]@{ name='fixture-bucket' }) }
            Mock Get-CaGcpBucketName { 'fixture-bucket' }
            Mock Invoke-CaGcloudJson {
                [pscustomobject]@{ Success=$false; State='Denied'; Text='PERMISSION_DENIED'; Error='PERMISSION_DENIED'; Json=$null }
            }

            (Test-CaGcpPublicBuckets).Status | Should -Be 'Error'
        }
    }
}

Describe 'Claudit Entra policy scope regressions' {
    InModuleScope Claudit {
        It 'rejects MFA policies with user exclusions as broad coverage' {
            $policy = [pscustomobject]@{
                State='enabled'
                Conditions=[pscustomobject]@{
                    Users=[pscustomobject]@{ IncludeUsers=@('All'); ExcludeUsers=@('breakglass'); ExcludeGroups=@(); ExcludeRoles=@() }
                    Applications=[pscustomobject]@{ IncludeApplications=@('All'); ExcludeApplications=@() }
                }
                GrantControls=[pscustomobject]@{ BuiltInControls=@('mfa'); AuthenticationStrength=$null }
            }

            (Test-CaConditionalAccessCoversAllUsersAndApps -Policy $policy) | Should -BeFalse
            @(Get-CaBroadMfaPolicies -Policies @($policy)).Count | Should -Be 0
        }

        It 'accepts only an enabled, exclusion-free all-users/all-apps MFA policy' {
            $policy = [pscustomobject]@{
                State='enabled'
                Conditions=[pscustomobject]@{
                    Users=[pscustomobject]@{ IncludeUsers=@('All'); ExcludeUsers=@(); ExcludeGroups=@(); ExcludeRoles=@() }
                    Applications=[pscustomobject]@{ IncludeApplications=@('All'); ExcludeApplications=@() }
                }
                GrantControls=[pscustomobject]@{ BuiltInControls=@('mfa'); AuthenticationStrength=$null }
            }

            @(Get-CaBroadMfaPolicies -Policies @($policy)).Count | Should -Be 1
        }
    }
}

Describe 'Claudit Azure Graph pagination' {
    InModuleScope Claudit {
        It 'collects every page and reports the page count' {
            Mock Invoke-CaAzRestJson {
                if ($Uri -eq 'https://graph.test/page/1') {
                    return [pscustomobject]@{
                        Success=$true; State='Ok'; Text=''
                        Json=[pscustomobject]@{ value=@([pscustomobject]@{ id='one' }); '@odata.nextLink'='https://graph.test/page/2' }
                    }
                }
                [pscustomobject]@{
                    Success=$true; State='Ok'; Text=''
                    Json=[pscustomobject]@{ value=@([pscustomobject]@{ id='two' }) }
                }
            }

            $result = Invoke-CaAzGraphCollection -Uri 'https://graph.test/page/1'

            $result.Success | Should -BeTrue
            @($result.Json.value).Count | Should -Be 2
            $result.Json.PageCount | Should -Be 2
            Should -Invoke Invoke-CaAzRestJson -Times 2
        }
    }
}

Describe 'Claudit VPS SSH argument safety' {
    InModuleScope Claudit {
        It 'rejects an option-shaped target before executing ssh' {
            Mock Get-CaProviderOption {
                [pscustomobject]@{ Target='-V'; SshUser=''; SshPort=22; AllowedPublicPorts=@() }
            }
            Mock Invoke-CaExternalCommand { throw 'must not execute' }

            { Invoke-CaVpsCommand -Script 'id' } | Should -Throw '*Unsafe SSH target*'
            Should -Invoke Invoke-CaExternalCommand -Times 0
        }

        It 'inserts the option terminator before a valid target' {
            Mock Get-CaProviderOption {
                [pscustomobject]@{ Target='host.example'; SshUser='audit'; SshPort=22; AllowedPublicPorts=@() }
            }
            Mock Invoke-CaExternalCommand {
                [pscustomobject]@{ Success=$true; State='Ok'; ExitCode=0; Text='' }
            }

            Invoke-CaVpsCommand -Script 'id' | Out-Null

            Should -Invoke Invoke-CaExternalCommand -Times 1 -ParameterFilter {
                $Command -eq 'ssh' -and $Arguments[4] -eq '--' -and $Arguments[5] -eq 'audit@host.example'
            }
        }
    }
}

Describe 'Claudit temporary authentication profile hygiene' {
    InModuleScope Claudit {
        It 'verifies removal of the temporary browser profile' {
            $profile = Join-Path $TestDrive 'browser-profile'
            New-Item -ItemType Directory -Path $profile | Out-Null
            Set-Content -LiteralPath (Join-Path $profile 'session-artifact') -Value 'fixture'

            Remove-CaTemporaryBrowserProfile -ProfilePath $profile

            Test-Path -LiteralPath $profile | Should -BeFalse
        }
    }
}
