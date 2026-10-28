# setup_seeker.ps1 - sets mine.seeker.listen / token in wallet\proxi.yaml (only when empty) and writes seeker.txt
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$prof = Join-Path $dir 'wallet\proxi.yaml'
if (-not (Test-Path $prof)) { Write-Host 'wallet\proxi.yaml not found: create the wallet first.'; exit 1 }
$y = [IO.File]::ReadAllText($prof)
$reL = '(?m)^([ \t]+listen:)[ \t]*(\S*)[ \t]*(\r?)$'
$reT = '(?m)^([ \t]+token:)[ \t]*(\S*)[ \t]*(\r?)$'
$m = [regex]::Match($y, $reL)
$t = [regex]::Match($y, $reT)
if (-not $m.Success -or -not $t.Success) { Write-Host 'no mine.seeker listen / token lines in wallet\proxi.yaml (old proxi?)'; exit 1 }
$listen = $m.Groups[2].Value
if ($listen -eq '') {
    $listen = '127.0.0.1:8100'
    $y = ([regex]$reL).Replace($y, { param($x) $x.Groups[1].Value + ' ' + $listen + $x.Groups[3].Value }, 1)
}
$token = $t.Groups[2].Value
if ($token -eq '') {
    $b = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    $token = -join ($b | ForEach-Object { $_.ToString('x2') })
    $y = ([regex]$reT).Replace($y, { param($x) $x.Groups[1].Value + ' ' + $token + $x.Groups[3].Value }, 1)
}
[IO.File]::WriteAllText($prof, $y, (New-Object Text.UTF8Encoding($false)))
$seeker = "--proxi http://$listen --token $token"
[IO.File]::WriteAllText((Join-Path $dir 'seeker.txt'), $seeker + "`r`n", (New-Object Text.UTF8Encoding($false)))
Write-Host "mine.seeker.listen = $listen, token set; seeker.txt written."
