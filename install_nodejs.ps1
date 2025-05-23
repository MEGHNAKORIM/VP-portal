# Download Node.js LTS installer
$nodeUrl = "https://nodejs.org/dist/v18.16.0/node-v18.16.0-x64.msi"
$installerPath = "$env:TEMP\nodejs_installer.msi"

Write-Host "Downloading Node.js installer..."
Invoke-WebRequest -Uri $nodeUrl -OutFile $installerPath

# Install Node.js
Write-Host "Installing Node.js..."
Start-Process msiexec.exe -Wait -ArgumentList "/i $installerPath /quiet"

# Clean up
Remove-Item $installerPath

Write-Host "Node.js installation completed. Please restart your terminal to use Node.js and npm."
