$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$commandPath = $MyInvocation.MyCommand.Path

if (-not $isAdministrator) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$commandPath`""
    Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs -Wait
    exit
}

$scrName = "sgcc_ss.scr"
$rootPath = Split-Path -Parent $commandPath
$sourcePath = Join-Path $rootPath $scrName
New-Item -Path "C:\sgcc_ss" -ItemType Directory -Force
$destPath = Join-Path "C:\sgcc_ss" $scrName
Copy-Item -Path $sourcePath -Destination $destPath -Force

# remove group policies
$lgpoPath = Join-Path $rootPath "LGPO.exe"
$policiesPath = Join-Path $rootPath "policies.txt"
& $lgpoPath /t $policiesPath
gpupdate.exe /force

$regPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "SCRNSAVE.EXE" -Value $destPath
Set-ItemProperty -Path $regPath -Name "ScreenSaveActive" -Value "1"
Set-ItemProperty -Path $regPath -Name "ScreenSaverIsSecure" -Value "1"
Set-ItemProperty -Path $regPath -Name "ScreenSaveTimeOut" -Value "300"

# delete previous Jiansong's reg
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "pb" -ErrorAction SilentlyContinue
Remove-Item -Path "C:\pb" -Force -Recurse -ErrorAction SilentlyContinue
