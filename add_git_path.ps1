$gitPath='C:\Program Files\Git\cmd'
$u=[Environment]::GetEnvironmentVariable('Path','User')
if (-not $u) { $u = '' }
if ($u -notlike "*${gitPath}*") {
    [Environment]::SetEnvironmentVariable('Path', ($u + ';' + $gitPath).Trim(';'), 'User')
    Write-Output "Added to user PATH: $gitPath"
} else {
    Write-Output "Git path already in user PATH"
}
Write-Output "Machine PATH (first 5 entries):"
[Environment]::GetEnvironmentVariable('Path','Machine') -split ';' | Select-Object -First 5
Write-Output "User PATH (first 5 entries):"
[Environment]::GetEnvironmentVariable('Path','User') -split ';' | Select-Object -First 5
