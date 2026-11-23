# Builds lg-blackbox.zip: the plugin ready to upload (Plugins > Add New > Upload Plugin).
# Entries use forward slashes and the top folder is lg-blackbox/, as WordPress expects.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$root = $PSScriptRoot
$out = Join-Path $root 'lg-blackbox.zip'
if (Test-Path $out) { Remove-Item $out }
$zip = [System.IO.Compression.ZipFile]::Open($out, 'Create')
foreach ($f in 'gate.php', 'lg-blackbox.php', 'probe.php', 'assets/lgbb-ui.css', 'assets/lgbb-ui.js') {
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $root ($f -replace '/', '\')), "lg-blackbox/$f")
}
$zip.Dispose()
Write-Host "Built $out"
