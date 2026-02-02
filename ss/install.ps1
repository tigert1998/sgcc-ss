$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$commandPath = $MyInvocation.MyCommand.Path

if (-not $isAdministrator) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$commandPath`""
    Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs -Wait
    exit
}

$sourcePath = Join-Path (Split-Path -Parent $commandPath) "screen_saver.scr"
$destPath = "C:\screen_saver.scr"
Copy-Item -Path $sourcePath -Destination $destPath -Force
$regPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "SCRNSAVE.EXE" -Value $destPath
Set-ItemProperty -Path $regPath -Name "ScreenSaveActive" -Value "1"
Set-ItemProperty -Path $regPath -Name "ScreenSaverIsSecure" -Value "1"
Set-ItemProperty -Path $regPath -Name "ScreenSaveTimeOut" -Value "300"

# delete previous Jiansong's reg
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "pb" -ErrorAction SilentlyContinue
