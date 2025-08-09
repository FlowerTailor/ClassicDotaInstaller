#requires -version 5.1
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Path $scriptPath -Parent
$installer = Join-Path $scriptDir 'Install-Dota684.ps1'
if (-not (Test-Path -LiteralPath $installer)) {
    [System.Windows.Forms.MessageBox]::Show("Installer not found: $installer","Error","OK","Error") | Out-Null
    exit 1
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Dota 2 Classic 6.84 Installer Wizard'
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.Size = New-Object System.Drawing.Size(560, 360)

$y = 20

$lblDir = New-Object System.Windows.Forms.Label
$lblDir.Text = 'Install directory:'
$lblDir.Location = New-Object System.Drawing.Point(12,$y)
$lblDir.AutoSize = $true
$form.Controls.Add($lblDir)

$txtDir = New-Object System.Windows.Forms.TextBox
$txtDir.Size = New-Object System.Drawing.Size(350,22)
$txtDir.Location = New-Object System.Drawing.Point(120,($y - 3))
$txtDir.Text = 'C:\\Program Files\\classicdota'
$form.Controls.Add($txtDir)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = 'Browse...'
$btnBrowse.Size = New-Object System.Drawing.Size(70,24)
$btnBrowse.Location = New-Object System.Drawing.Point(480,($y - 4))
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Choose installation folder'
    $dlg.SelectedPath = $txtDir.Text
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtDir.Text = $dlg.SelectedPath
    }
})
$form.Controls.Add($btnBrowse)

$y += 40

${null} = 0
$grpSource = New-Object System.Windows.Forms.GroupBox
$grpSource.Text = 'Install source'
$grpSource.Location = New-Object System.Drawing.Point(12,$y)
$grpSource.Size = New-Object System.Drawing.Size(520, 70)
$form.Controls.Add($grpSource)

$lblLocal = New-Object System.Windows.Forms.Label
$lblLocal.Text = 'Local archive (ZIP/7z):'
$lblLocal.Location = New-Object System.Drawing.Point(10,22)
$lblLocal.AutoSize = $true
$grpSource.Controls.Add($lblLocal)

$txtLocal = New-Object System.Windows.Forms.TextBox
$txtLocal.Size = New-Object System.Drawing.Size(330,22)
$txtLocal.Location = New-Object System.Drawing.Point(150,20)
$grpSource.Controls.Add($txtLocal)

$btnLocalBrowse = New-Object System.Windows.Forms.Button
$btnLocalBrowse.Text = 'Browse...'
$btnLocalBrowse.Size = New-Object System.Drawing.Size(70,22)
$btnLocalBrowse.Location = New-Object System.Drawing.Point(485,20)
$btnLocalBrowse.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'Archives (*.zip;*.7z)|*.zip;*.7z|All files (*.*)|*.*'
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $txtLocal.Text = $ofd.FileName }
})
$grpSource.Controls.Add($btnLocalBrowse)

$y += 90

$chkPrereqs = New-Object System.Windows.Forms.CheckBox
$chkPrereqs.Text = 'Install prerequisites (DirectX June 2010, VC++ runtimes)'
$chkPrereqs.Location = New-Object System.Drawing.Point(12,$y)
$chkPrereqs.AutoSize = $true
$chkPrereqs.Checked = $true
$form.Controls.Add($chkPrereqs)

$y += 26
$chkHosts = New-Object System.Windows.Forms.CheckBox
$chkHosts.Text = 'Block www.dota2.com in hosts (reduce lag, can revert later)'
$chkHosts.Location = New-Object System.Drawing.Point(12,$y)
$chkHosts.AutoSize = $true
$chkHosts.Checked = $true
$form.Controls.Add($chkHosts)

$y += 26
$chkQueue = New-Object System.Windows.Forms.CheckBox
$chkQueue.Text = 'Open queue/sign-in after install'
$chkQueue.Location = New-Object System.Drawing.Point(12,$y)
$chkQueue.AutoSize = $true
$chkQueue.Checked = $true
$form.Controls.Add($chkQueue)

$y += 26
$chkNoAdmin = New-Object System.Windows.Forms.CheckBox
$chkNoAdmin.Text = 'Test mode (NoAdmin): skip firewall/hosts/prereqs'
$chkNoAdmin.Location = New-Object System.Drawing.Point(12,$y)
$chkNoAdmin.AutoSize = $true
$chkNoAdmin.Checked = $false
$form.Controls.Add($chkNoAdmin)

$y += 40

$btnStart = New-Object System.Windows.Forms.Button
$btnStart.Text = 'Start Install'
$btnStart.Size = New-Object System.Drawing.Size(120,30)
$btnStart.Location = New-Object System.Drawing.Point(292,$y)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = 'Cancel'
$btnCancel.Size = New-Object System.Drawing.Size(120,30)
$btnCancel.Location = New-Object System.Drawing.Point(414,$y)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.AutoSize = $true
$lblStatus.Location = New-Object System.Drawing.Point(12,($y + 6))
$lblStatus.Text = ''

$form.Controls.Add($btnStart)
$form.Controls.Add($btnCancel)
$form.Controls.Add($lblStatus)

$btnCancel.Add_Click({ $form.Close() })

$btnStart.Add_Click({
    $installDir = $txtDir.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($installDir)) {
        [System.Windows.Forms.MessageBox]::Show('Please choose an installation directory.','Missing input','OK','Warning') | Out-Null
        return
    }

    $psArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File', '"' + $installer + '"', '"-InstallDir=' + $installDir + '"')
    if ($txtLocal.Text.Trim()) { $psArgs += ('"-LocalArchive=' + $txtLocal.Text.Trim() + '"') }
    if (-not $txtLocal.Text.Trim()) {
        [System.Windows.Forms.MessageBox]::Show('Please select a local archive (ZIP/7z).','Missing input','OK','Warning') | Out-Null
        return
    }
    if ($chkPrereqs.Checked) { $psArgs += '-InstallPrereqs' }
    if ($chkHosts.Checked) { $psArgs += '-BlockDota2Site' }
    if ($chkQueue.Checked) { $psArgs += '-OpenQueue' }
    if ($chkNoAdmin.Checked) { $psArgs += '-NoAdmin' }

    $lblStatus.Text = 'Installer running in a console window. This wizard will close when it finishes.'
    $btnStart.Enabled = $false
    $btnCancel.Enabled = $false

    try {
        if ($chkNoAdmin.Checked) {
            Start-Process -FilePath 'powershell.exe' -ArgumentList ($psArgs -join ' ') -Wait -WindowStyle Normal
        } else {
            # Elevate up front and run in a visible console, wait for completion
            Start-Process -FilePath 'powershell.exe' -ArgumentList ($psArgs -join ' ') -Verb RunAs -Wait -WindowStyle Normal
        }
        $form.Close()
    } catch {
        [System.Windows.Forms.MessageBox]::Show('Failed to launch installer: ' + $_.Exception.Message,'Error','OK','Error') | Out-Null
        $btnStart.Enabled = $true
        $btnCancel.Enabled = $true
        $lblStatus.Text = ''
    }
})

[void]$form.ShowDialog()


