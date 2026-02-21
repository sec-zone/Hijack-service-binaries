$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)

Get-CimInstance Win32_Service |
Where-Object {
    $_.PathName -and
    $_.PathName -notmatch "system32|svchost"
} |
ForEach-Object {

    $exe = ($_.PathName -replace '"','') -split '\.exe' | Select-Object -First 1
    $exe = "$exe.exe"

    if (Test-Path $exe) {

        $acl = Get-Acl $exe

        foreach ($ace in $acl.Access) {


            if ($ace.AccessControlType -eq "Allow") {

                if ($currentPrincipal.IsInRole($ace.IdentityReference)) {

                    $rights = $ace.FileSystemRights

                    $danger =
                        $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::Write) -or
                        $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::Modify) -or
                        $rights.HasFlag([System.Security.AccessControl.FileSystemRights]::FullControl)

                    if ($danger) {

                        Write-Host "⚠️ Current user CAN modify service binary!" -ForegroundColor Red
                        Write-Host "Service: $($_.Name)"
                        Write-Host "Runs As: $($_.StartName)"
                        Write-Host "Path: $exe"
                        Write-Host "Matched Identity: $($ace.IdentityReference)"
                        Write-Host "Rights: $rights"
                        Write-Host "-------------------------------------`n"
                    }
                }
            }
        }
    }
}
