#!/usr/bin/env pwsh
# Build the cdylib, generate the Kotlin bindings, compile them with the JVM test
# using a downloaded kotlinc (no Gradle), and run it. Needs cargo and a JDK (21).
# Usage: pwsh ffi/kotlin/run-tests.ps1
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$KotlinVersion = '2.4.20'
$JnaVersion = '5.19.1'

$here = $PSScriptRoot
$root = (Resolve-Path (Join-Path $here '../..')).Path
$cache = Join-Path $here '.cache'
$generated = Join-Path $here 'generated'
New-Item -ItemType Directory -Force $cache | Out-Null

$kotlinHome = Join-Path $cache "kotlinc-$KotlinVersion"
if (-not (Test-Path (Join-Path $kotlinHome 'kotlinc/lib/kotlin-compiler.jar'))) {
    $zip = Join-Path $cache "kotlin-compiler-$KotlinVersion.zip"
    Write-Host "downloading kotlin-compiler $KotlinVersion"
    Invoke-WebRequest "https://github.com/JetBrains/kotlin/releases/download/v$KotlinVersion/kotlin-compiler-$KotlinVersion.zip" -OutFile $zip
    Expand-Archive $zip -DestinationPath $kotlinHome -Force
    Remove-Item $zip
}
$jna = Join-Path $cache "jna-$JnaVersion.jar"
if (-not (Test-Path $jna)) {
    Write-Host "downloading jna $JnaVersion"
    Invoke-WebRequest "https://repo1.maven.org/maven2/net/java/dev/jna/jna/$JnaVersion/jna-$JnaVersion.jar" -OutFile $jna
}

Push-Location $root
try {
    cargo build -p device-pairing-ffi --release --locked
    $libName = if ($IsWindows) { 'device_pairing_ffi.dll' } elseif ($IsMacOS) { 'libdevice_pairing_ffi.dylib' } else { 'libdevice_pairing_ffi.so' }
    $libDir = Join-Path $root 'target/release'
    $lib = Join-Path $libDir $libName
    if (Test-Path $generated) { Remove-Item -Recurse -Force $generated }
    cargo run -q -p device-pairing-ffi --bin uniffi-bindgen --locked -- generate --library $lib --language kotlin --out-dir $generated --no-format

    $kotlinc = Join-Path $kotlinHome ($IsWindows ? 'kotlinc/bin/kotlinc.bat' : 'kotlinc/bin/kotlinc')
    $jar = Join-Path $cache 'pairing-test.jar'
    $sources = @(Get-ChildItem -Recurse -Filter *.kt $generated, (Join-Path $here 'test') | ForEach-Object FullName)
    Write-Host "kotlinc $($sources.Count) files"
    & $kotlinc -nowarn -cp $jna @sources -include-runtime -d $jar

    $sep = [IO.Path]::PathSeparator
    java "-Djna.library.path=$libDir" "-Duniffi.component.device_pairing.libraryOverride=$lib" -cp "$jar$sep$jna" PairingTestKt
}
finally {
    Pop-Location
}
