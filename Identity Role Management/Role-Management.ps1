<###########################################################################

 NAME: Manage Identity Roles using REST API

 AUTHOR: Jeff Rechten
 
 COMMENT: 
 This script will help in Role Management tasks

 VERSION HISTORY:
 0.1 	2024-04-05   	- Initial release

########################################################################### #>
# Usage examples
#  .\role-management.ps1 -tenant_id abc1234 -client_id radius_rest_user@cyberark.com.1234 -published_app_name Oauth2Client123 -scope_name All -RoleName TestRole123 -AddRole
#  .\role-management.ps1 -tenant_id abc1234 -client_id radius_rest_user@cyberark.com.1234 -published_app_name Oauth2Client123 -scope_name All -RoleName TestRole123 -UserName "test02@cybr.com" -AddRoleMember
#
# Import-Module ..\"Identity Authentication"\IdentityAuth.psm1
# $header = Get-IdentityHeader -IdentityTenantURL "something.id.cyberark.cloud" -IdentityUserName "UserToAuthenticate@cyberark.cloud.ID"
# .\role-management.ps1 -tenant_id abc1234 -token $header -RoleName TestRole123 -AddRole


param(
    [Parameter(Mandatory=$false, HelpMessage="Please enter the tenant ID.")]
    [string]$tenant_id,
    [Parameter(Mandatory=$false, HelpMessage="Please enter the client ID.")]
    [string]$client_id,
    [Parameter(Mandatory=$false, HelpMessage="Please enter the published app name.")]
    [string]$published_app_name,
    [Parameter(Mandatory=$false, HelpMessage="Please enter the scope name.")]
    [string]$scope_name = 'all',
    [Parameter(Mandatory=$false, HelpMessage="Please enter the token.")]
    [string]$token,
    [Parameter(Mandatory=$false, HelpMessage="Please enter the role name.")]
    [string]$RoleName,
    [Parameter(Mandatory=$false, HelpMessage="Please enter the user name.")]
    [string]$UserName,
    [Parameter(Mandatory=$false, HelpMessage="Please enter the input file name.")]
    [string]$InputFileCsvPath,
    [Parameter(Mandatory=$false)]
    [switch]$AddRole,
    [Parameter(Mandatory=$false)]
    [switch]$AddRoleMember,
    [Parameter(Mandatory=$false)]
    [switch]$RemoveRoleMember,
    [Parameter(Mandatory=$false)]
    [switch]$AddRoleOnUpdate
)

$cacheFilePath = ".\cacheFile.csv"

# Check if the user passes either the RoleName or passes $InputFileCsvPath
if (!$RoleName -and !$InputFileCsvPath) {
    Write-Error "Please pass either the RoleName / UserName or the InputFileCsvPath."
    return
}

# Check if the user passes only one of AddRole, AddRoleMember, or RemoveRoleMember, or InputFileCsvPath
$actionCount = [int]$AddRole.IsPresent + [int]$AddRoleMember.IsPresent + [int]$RemoveRoleMember.IsPresent
if (![string]::IsNullOrWhiteSpace($InputFileCsvPath)) {
    $actionCount++
}

if ($actionCount -ne 1) {
    Write-Error "Please pass only one of AddRole, AddRoleMember, RemoveRoleMember, or InputFileCsvPath."
    return
}


# Check if AddRoleOnUpdate is passed without AddRoleMember or with AddRole/RemoveRoleMember
if ($AddRoleOnUpdate -and (!$AddRoleMember -or $AddRole -or $RemoveRoleMember)) {
    Write-Error "AddRoleOnUpdate can only be passed with AddRoleMember and not with AddRole or RemoveRoleMember."
    return
}


# Prompt for tenant_id if not provided
if (!$tenant_id) {
    $tenant_id = Read-Host -Prompt "Please enter the tenant ID"
}

# Check if the tenant URLs resolve via DNS
$tenant_url1 = "$tenant_id.id.cyberark.cloud"
$tenant_url2 = "$tenant_id.my.idaptive.app"

if (Resolve-DnsName -Name $tenant_url1 -ErrorAction SilentlyContinue) {
    $tenant_url = $tenant_url1
} elseif (Resolve-DnsName -Name $tenant_url2 -ErrorAction SilentlyContinue) {
    $tenant_url = $tenant_url2
} else {
    Write-Error "Neither $tenant_url1 nor $tenant_url2 could be resolved via DNS."
    return
}

<#
# Get New Oauth2 Token only if needed
# Note, this script only supports OAuth2 Client Credentials Grant (Backend Application flow)
function Get-NewOAuth2Token {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$token_url,

        [Parameter(Mandatory = $true)]
        [string]$scope_name,

        [Parameter(Mandatory = $true)]
        [string]$client_id,

        [Parameter(Mandatory = $true)]
        [string]$client_secret
    )

    $credentials = New-Object System.Management.Automation.PSCredential ($client_id, ($client_secret | ConvertTo-SecureString -AsPlainText -Force))
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credentials.UserName + ':' + ($credentials.GetNetworkCredential()).Password))

    $headers = @{
        Authorization = "Basic $encodedCredentials"
        'Content-Type' = 'application/x-www-form-urlencoded'
    }
    $body = @{
        grant_type = 'client_credentials'
        scope = $scope_name
    }

    try {
        $response = Invoke-RestMethod -Uri $token_url -Method Post -Body $body -Headers $headers
        $access_token = $response.access_token
        Write-Verbose "Token acquired successfully"
        return $access_token
    } catch {
        Write-Error "Failed to retrieve OAuth2 token: $_"
        return $null
    }
}
#>

function Get-NewOauth2Token {
    param (
        [string]$token_url,
        [string]$scope_name,
        [string]$client_id,
        [string]$client_secret
    )
    try {
        $pair = "$($client_id):$($client_secret)"
        $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
        $basicAuthValue = "Basic $encodedCreds"
        $headers = @{
            Authorization = $basicAuthValue
            'Content-Type' = 'application/x-www-form-urlencoded'
        }
        $body = @{
            grant_type = 'client_credentials'
            scope = $scope_name
        }
        $response = Invoke-RestMethod -Uri $token_url -Method Post -Body $body -Headers $headers
        return $response.access_token, $response
    } catch {
        Write-Error "Failed to retrieve OAuth2 token: $_"
        return $null
    }
}


# If token is not provided, prompt for client_id and client_secret
if (!$token) {
    # Prompt for client_id if not provided
    if (!$client_id) {
        $client_id = Read-Host -Prompt "Please enter the client ID"
    }

    # Prompt for client_secret using Get-Credential
    $Creds = Get-Credential -Message "Please enter the client secret" -UserName $client_id
    $client_secret = $Creds.GetNetworkCredential().Password
	
	# Prompt for published_app_name if not provided
	if (!$published_app_name) {
		$published_app_name = Read-Host -Prompt "Please enter the published app name"
	}
	$token_url = 'https://' + $tenant_url + '/oauth2/token/' + $published_app_name
    Write-Verbose $token_url
	$access_token, $token_response = Get-NewOauth2Token $token_url $scope_name $client_id $client_secret

} else {
    $access_token = $token['Authorization'] -replace 'Bearer ', ''
	$client_id = $null
    $client_secret = $null
}



function Search-Roles ($rolename) {
    $url =  "https://" + $tenant_url + "/Redrock/query"
    $payload = @{
        Script = "Select * from Role WHERE RoleType = 'PrincipalList' and Name = '$rolename'"
        args = @{
            Caching = -1
        }
    }
    $headers = @{
        Accept = "*/*"
        'Content-Type' = 'application/json'
        Authorization = 'Bearer ' + $access_token
    }
    $response = Invoke-RestMethod -Uri $url -Method Post -Body ($payload | ConvertTo-Json) -Headers $headers -ContentType 'application/json'
    Write-Verbose $response.Result.Count
    if ($response.Result.Count -gt 0) {
        $roleID = $response.Result.Results[0].Row.ID
        return $roleID
    } elseif ($AddRoleOnUpdate) {
        return Add-Role -rolename $rolename -description "N/A"
    } else {
		return $null
	}
}

function Add-Role ($rolename, $description) {
    $url = "https://" + $tenant_url + "/Roles/StoreRole"
    $payload = @{
        Name = $rolename
        Description = "Role for $rolename : $description"
        RoleType = "PrincipalList"
    }
    $headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json, text/html'
        Authorization = 'Bearer ' + $access_token
    }
    $response = Invoke-RestMethod -Uri $url -Method Post -Body ($payload | ConvertTo-Json) -Headers $headers -ContentType 'application/json'
    return $response.Result._RowKey
	
}



# Find DS UUIDs 
function Search-DS ($username) {
    $url =  "https://" + $tenant_url + "/Core/GetDirectoryServices"

    $headers = @{
        Accept = '*/*'
        'Content-Type' = 'application/json'
        Authorization = 'Bearer ' + $access_token
    }
    $response = Invoke-RestMethod -Uri $url -Method Post -Body ($payload | ConvertTo-Json) -Headers $headers -ContentType 'application/json'
    if (($response.success) -And ($response.Result.Count -gt 0)) {
        $UUIDs = @()
        foreach ($result in $response.Result.Results) {
            $UUIDs += $result.Row.directoryServiceUuid
            Write-Verbose "UUID: $($result.Row.directoryServiceUuid)"
        }
        $UserId, $DirectoryUUID = Search-UserDS -username $username -DirectoryUUID $UUIDs
        if ($UserId) {
            return $UserId, $DirectoryUUID
        }
        
        # Condition: user not found
        return $null
    } else {
        Write-Host $response
        return $null
    }
}

# Find user uuid from systemname (upn)
function Search-UserDS ($username, $DirectoryUUIDs) {
    $url =  "https://" + $tenant_url + "/UserMgmt/DirectoryServiceQuery"

    $payload = @{
        # notworking user = @{SystemName = @{_like = $username}}
        user = "{`"SystemName`": {`"_like`":`"$username`"}}"
        directoryServices = $DirectoryUUIDs
        Args = @{
            PageNumber = 1
            PageSize = 1000
            Limit = 1000
            SortBy = ""
            Caching = -1
        }
    }
    $headers = @{
        Accept = '*/*'
        'Content-Type' = 'application/json'
        Authorization = 'Bearer ' + $access_token
    }
    Write-Verbose ($payload | ConvertTo-Json -Depth 6)
    $response = Invoke-RestMethod -Uri $url -Method Post -Body ($payload | ConvertTo-Json -Depth 5) -Headers $headers
    Write-Verbose ($response | ConvertTo-Json -Depth 6)
    if ($response.Result.User.Count -eq 1) {
        Write-Host "Found $username"
        Write-Verbose "Key: $($response.Result.User.Results[0].Entities[0].Key), DSUUID: $($response.Result.User.Results[0].Row.DirectoryServiceUuid)"
		return $response.Result.User.Results[0].Entities[0].Key, $response.Result.User.Results[0].Row.DirectoryServiceUuid
    } else {
        return $null
    }
}


# Add user uid to role via role name
function Add-UserToRole ($userkey, $rolename, $username, $DirectoryUUID) {
    $RoleID = Search-Roles -rolename $rolename
	$url = "https://" + $tenant_url + "/Roles/UpdateRoleV2"
    
    $payload = @{
        Users = @{
            Add = @(
                @{
                    Type = "User"
                    DirectoryServiceUuid = $DirectoryUUID
                    SystemName = $username
                    ExternalUuid = $userkey
                }
            )
        }
        Name = $roleid
    }
    $headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json, text/html'
        Authorization = 'Bearer ' + $access_token
    }
    Write-Verbose ($payload | ConvertTo-Json -Depth 6)
    $response = Invoke-RestMethod -Uri $url -Method Post -Body ($payload | ConvertTo-Json -Depth 6) -Headers $headers -ContentType 'application/json'
    Write-Verbose ($response | ConvertTo-Json -Depth 6)
    if ($response.success) {
        Write-Host "Added to $rolename"
    } else {
        Write-Host "Issue detected Add-UserToRole: with $userkey ; $roleid"
        #Write-Host ($response | ConvertTo-Json)
    }
}



# Find role member GID
function Get-RoleMemberID ($username, $roleid) {
	$url = "https://" + $tenant_url + "/Roles/GetRoleMembers"
    $params = @{
        name = $roleid
    }

    $headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json, text/html'
        Authorization = 'Bearer ' + $access_token
    }
    $queryString = ($params.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"

    # Append query string to URL
    $fullUrl = "$($url)?$($queryString)"

    $response = Invoke-RestMethod -Uri $fullUrl -Method Post -Headers $headers -ContentType 'application/json'
    if (($response.success) -And ($response.Result.Count -gt 0)) {
        foreach ($result in $response.Result.Results) {
            if ($username == $result.Row.Name){
                return $result.Row.Guid
            }
        }
        return $null
    } else {
        Write-Host "issue detected with $username ; $roleid"
        Write-Host $response
    }
}

# Remove user uid to role via username and role name
function Remove-UserFromRole ($UserName, $rolename) {
    $RoleID = Search-Roles -rolename $rolename
    $userkey = Get-RoleMemberID -username $UserName -roleid $RoleID
	$url = "https://" + $tenant_url + "/Roles/UpdateRoleV2"
    
    $payload = @{
        Users = @{
            Delete = @($userkey)
        }
        Name = $roleid
    }
    $headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json, text/html'
        Authorization = 'Bearer ' + $access_token
    }
    $response = Invoke-RestMethod -Uri $url -Method Post -Body ($payload | ConvertTo-Json) -Headers $headers -ContentType 'application/json'
    if ($response.success) {
        Write-Host "Removed $Username from $rolename"
    } else {
        Write-Host "issue detected with $userkey ; $roleid"
    }
}

function Get-CacheData {
    if (Test-Path $cacheFilePath) {
        $useCache = Read-Host "Cache file found. Do you want to use cached data to skip previously processed entries? (Y/N)"
        if ($useCache -eq 'Y') {
            return Import-Csv -Path $cacheFilePath | ForEach-Object { "$($_.UserName),$($_.RoleName)" }
        }
    }
    return @{}
}

function Save-CacheData ($Cache) {
    $Cache | ForEach-Object {
        $keyValue = $_.Split(',')
        [PSCustomObject]@{
            UserName = $keyValue
            RoleName = $keyValue
        }
    } | Export-Csv -Path $cacheFilePath -NoTypeInformation
}




if ($InputFileCsvPath) {
    $addedPairs = Get-CacheData
    Import-Csv -Path $InputFileCsvPath | ForEach-Object {
        $userName = $_.user
        $roleName = $_.role
        $cacheKey = "$userName,$roleName"

        Write-Host "Processing $userName for role $roleName."

        if (-not $addedPairs.ContainsKey($cacheKey)) {
            $userId, $directoryUUID = Search-DS -username $userName
            if ($userId) {
                Add-UserToRole -userKey $userId -roleName $roleName -userName $userName -directoryUUID $directoryUUID
                $addedPairs[$cacheKey] = $true
            } else {
                Write-Host "No user found for $userName."
            }
        } else {
            Write-Host "Skipping $userName for role $roleName as it has already been added."
        }
    }

    Save-CacheData -Cache $addedPairs.Keys
}

<##
if ($InputFileCsvPath) {
	# Read CSV and process each row
	$added_pairs = @()
	Import-Csv -Path $InputFileCsvPath | ForEach-Object {
		$UserName = $_.user
		$RoleName = $_.role
		Write-Host $user
		if ($added_pairs -notcontains @($user, $role)) {
			$UserId, $DirectoryUUID = Search-DS -username $UserName
			if ($UserId) {
                Add-UserToRole -userkey $UserId -rolename $RoleName -username $UserName -DirectoryUUID $DirectoryUUID
                $added_pairs += ,@($user, $role)
            } else {
                Write-Host "No user found."
            }
		} else {
			Write-Host "Skipping $user for role $role as it has already been added."
		}
	}
}
#>
if ($AddRole) {
	Add-Role -rolename $RoleName -description ""
}

if ($AddRoleMember) {
	$UserId, $DirectoryUUID = Search-DS -username $UserName
    if ($UserId) {
        Add-UserToRole -userkey $UserId -rolename $RoleName -username $UserName -DirectoryUUID $DirectoryUUID 
    } else {
        Write-Host "No user found."
    }
}

if ($RemoveRoleMember) {
	$UserId, $DirectoryUUID = Search-DS -username $UserName
    if ($UserId) {
        Remove-UserFromRole -username $UserName -rolename $RoleName 
    } else {
        Write-Host "No user found."
    }
}

Write-Host "Completed."
