#!/usr/bin/env pwsh
<#
.SYNOPSIS
    PowerShell-аналог утилиты logrotate из Linux
.DESCRIPTION
    Скрипт для ротации, сжатия и управления файлами журналов.
    Поддерживает функционал оригинальной утилиты logrotate.
.PARAMETER ConfigFile
    Путь к конфигурационному файлу logrotate
.PARAMETER State
    Путь к файлу состояния
.PARAMETER Force
    Принудительная ротация файлов журналов
.PARAMETER f
    Алиас для Force - принудительная ротация файлов журналов
.PARAMETER Verbose
    Подробный вывод
.PARAMETER Debug
    Режим отладки
.PARAMETER Mail
    Email для отправки отчетов
.PARAMETER Test
    Тестовый режим (без внесения изменений)
.EXAMPLE
    .\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf"
.EXAMPLE
    .\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf" -Force -Verbose
.EXAMPLE
    .\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf" -Test
.NOTES
    Версия: 1.0
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$ConfigFile = ".\logrotate.conf",
    
    [Parameter(Mandatory = $false)]
    [string]$State = ".\logrotate-state.json",
    
    [Parameter(Mandatory = $false)]
    [switch]$Force,
    
    [Parameter(Mandatory = $false)]
    [Alias("f")]
    [switch]$ForceAlias,
    
    [Parameter(Mandatory = $false)]
    [switch]$Test,
    
    [Parameter(Mandatory = $false)]
    [string]$Mail,
    
    [Parameter(Mandatory = $false)]
    [switch]$Install
)

# Функция для проверки окружения
function Test-LogRotateEnvironment {
    $result = @{
        IsValid = $true
        Messages = @()
    }
    
    $psVersion = $PSVersionTable.PSVersion
    $minPSVersion = [Version]"3.0"
    
    if ($psVersion -lt $minPSVersion) {
        $result.IsValid = $false
        $result.Messages += "Требуется PowerShell версии $minPSVersion или выше. Текущая версия: $psVersion"
    }
    else {
        $result.Messages += "PowerShell версии $psVersion соответствует требованиям."
    }
    
    $osInfo = [System.Environment]::OSVersion
    
    if ($osInfo.Platform -ne 'Win32NT') {
        $result.IsValid = $false
        $result.Messages += "Скрипт предназначен для запуска на Windows. Обнаружена ОС: $($osInfo.Platform)"
    }
    else {
        $result.Messages += "Операционная система: Windows $($osInfo.Version)"
    }
    
    if (-not (Test-Administrator)) {
        $result.IsValid = $false
        $result.Messages += "Скрипт должен быть запущен с правами администратора"
    }
    else {
        $result.Messages += "Запущено с правами администратора: Да"
    }
    
    try {
        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $result.Messages += "Модуль планировщика задач доступен."
        }
        else {
            $result.Messages += "Модуль планировщика задач недоступен. Функция установки планировщика может работать некорректно."
        }
    }
    catch {
        $result.Messages += "Ошибка при проверке модулей: $_"
    }
    
    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllText($tempFile, "Logrotate environment test")
        [System.IO.File]::Delete($tempFile)
        $result.Messages += "Доступ к файловой системе: ОК"
    }
    catch {
        $result.IsValid = $false
        $result.Messages += "Ошибка доступа к файловой системе: $_"
    }
    
    return $result
}

# Функция для проверки прав администратора
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Функция для проверки, занят ли файл другим процессом
function Test-FileLocked {
    param (
        [parameter(Mandatory = $true)][string]$FilePath
    )
    
    try {
        $fileInfo = New-Object System.IO.FileInfo $FilePath
        $fileStream = $fileInfo.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        
        if ($fileStream) {
            $fileStream.Close()
            $fileStream.Dispose()
            return $false
        }
    }
    catch {
        return $true
    }
    
    return $false
}

function Requires-AdminPrivileges {
    param (
        [string]$ConfigFile,
        [switch]$Install,
        [switch]$Force,
        [switch]$Test
    )
    
    if ($Install) {
        return $true
    }
    
    if (Test-Path $ConfigFile) {
        $systemPaths = @(
            "$env:SystemRoot",
            "$env:ProgramFiles",
            "${env:ProgramFiles(x86)}",
            "$env:windir",
            "$env:SystemDrive\Windows"
        )
        
        $content = Get-Content $ConfigFile -Raw
        
        foreach ($path in $systemPaths) {
            if ($content.Contains($path)) {
                Write-Host "Обнаружен системный путь в конфигурации: $path" -ForegroundColor Yellow
                return $true
            }
        }
        
        $protectedPaths = @()
        
        if ($content -match "olddir\s+([^\s]+)") {
            $olddir = $matches[1].Trim().Trim('"').Trim("'")
            $protectedPaths += $olddir
        }
        
        $filePatterns = @()
        $lines = $content -split "`n"
        foreach ($line in $lines) {
            $line = $line.Trim()
            if ($line -match "^([^{]+)\s*\{") {
                $pattern = $matches[1].Trim().Trim('"').Trim("'")
                $filePatterns += $pattern -split "\s+"
            }
        }
        
        foreach ($path in ($protectedPaths + $filePatterns)) {
            foreach ($systemPath in $systemPaths) {
                if ($path.StartsWith($systemPath)) {
                    Write-Host "Обнаружен защищенный путь: $path" -ForegroundColor Yellow
                    return $true
                }
            }
            
            if (-not ($path.Contains("*") -or $path.Contains("?"))) {
                if (Test-Path $path) {
                    try {
                        if (Test-Path $path -PathType Container) {
                            $testFile = Join-Path -Path $path -ChildPath "logrotate_permission_test.tmp"
                            [System.IO.File]::Create($testFile).Close()
                            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                        }
                        else {
                            $testAccess = [System.IO.File]::OpenWrite($path)
                            $testAccess.Close()
                            $testAccess.Dispose()
                        }
                    }
                    catch {
                        Write-Host "Требуются права администратора для доступа к пути: $path" -ForegroundColor Yellow
                        return $true
                    }
                }
            }
        }
    }
    
    return $false
}

# Установка ForceAlias как алиаса для Force
if ($ForceAlias) {
    $Force = $true
}

# Проверка окружения перед запуском скрипта
$envCheck = Test-LogRotateEnvironment
if (-not $envCheck.IsValid) {
    Write-Host "ОШИБКА: Скрипт не может быть запущен в текущем окружении" -ForegroundColor Red
    foreach ($message in $envCheck.Messages) {
        Write-Host " - $message" -ForegroundColor Yellow
    }
    exit 1
}
else {
    Write-Host "Проверка окружения выполнена успешно:" -ForegroundColor Green
    foreach ($message in $envCheck.Messages) {
        Write-Host " - $message" -ForegroundColor Gray
    }
}

# Установка сервиса планировщика задач
if ($Install) {
    Install-LogrotateScheduledTask
    return
}

#region Вспомогательные функции
function Write-LogRotateMessage {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timestamp [$Level] $Message"
}

function Install-LogrotateScheduledTask {
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = Split-Path -Parent $scriptPath
    $taskName = "LogRotate"
    $taskDescription = "Автоматическая ротация логов (аналог logrotate.timer)"
    
    if (-not (Test-Administrator)) {
        Write-LogRotateMessage "Для установки задачи планировщика требуются права администратора" "ERROR"
        exit 1
    }
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ConfigFile `"$scriptDir\logrotate.conf`""
    $trigger = New-ScheduledTaskTrigger -Daily -At "00:00"
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -WakeToRun
    
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description $taskDescription -Force
        Write-LogRotateMessage "Задача '$taskName' успешно установлена в планировщик задач." "SUCCESS"
    }
    catch {
        Write-LogRotateMessage "Ошибка при регистрации задачи в планировщике: $_" "ERROR"
        exit 1
    }
}

function Get-StateData {
    if (Test-Path $State) {
        try {
            $stateContent = Get-Content $State -Raw
            if ([string]::IsNullOrWhiteSpace($stateContent)) {
                Write-LogRotateMessage "Файл состояния пуст, используем пустую хэш-таблицу" "INFO"
                return @{}
            }
            
            $stateObj = ConvertFrom-Json -InputObject $stateContent -ErrorAction Stop
            
            $stateData = @{}
            if ($stateObj -ne $null) {
                $stateObj.PSObject.Properties | ForEach-Object {
                    $stateData[$_.Name] = $_.Value
                }
            }
            
            return $stateData
        }
        catch {
            Write-LogRotateMessage "Ошибка при чтении файла состояния: $_" "ERROR"
            try {
                $bakFile = "$State.$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
                Copy-Item -Path $State -Destination $bakFile -Force
                Write-LogRotateMessage "Создана резервная копия файла состояния: $bakFile" "INFO"
            }
            catch {
                Write-LogRotateMessage "Не удалось создать резервную копию файла состояния: $_" "WARNING"
            }
            
            return @{}
        }
    }
    else {
        return @{}
    }
}

function Save-StateData {
    param (
        [hashtable]$StateData
    )
    
    try {
        if (-not ($StateData -is [hashtable])) {
            Write-LogRotateMessage "StateData не является хэш-таблицей, преобразуем в хэш-таблицу" "WARNING"
            $newStateData = @{}
            foreach ($key in $StateData.PSObject.Properties.Name) {
                $newStateData[$key] = $StateData.$key
            }
            $StateData = $newStateData
        }
        
        $jsonContent = $StateData | ConvertTo-Json -Depth 4
        Set-Content -Path $State -Value $jsonContent -Force
        Write-LogRotateMessage "Файл состояния успешно сохранен: $State" "INFO"
    }
    catch {
        Write-LogRotateMessage "Ошибка при сохранении файла состояния: $_" "ERROR"
    }
}

function Test-ShouldRotate {
    param (
        [string]$File,
        [PSCustomObject]$Config,
        [hashtable]$StateData
    )
    
    if (-not (Test-Path $File)) {
        return $false
    }
    
    $fileInfo = Get-Item $File
    $lastRotationTime = $null
    
    if ($StateData.ContainsKey($File)) {
        $lastRotationTime = [datetime]$StateData[$File].lastRotation
    }
    
    # Проверка по maxage
    if ($Config.maxage -ne $null) {
        try {
            $maxAgeValue = $Config.maxage -replace "[^0-9]", ""
            if (-not [string]::IsNullOrEmpty($maxAgeValue)) {
                $maxAgeDays = [int]$maxAgeValue
                
                $fileAge = (Get-Date) - $fileInfo.LastWriteTime
                $fileAgeDays = $fileAge.TotalDays
                
                if ($fileAgeDays -lt $maxAgeDays) {
                    if ($Force) {
                        Write-LogRotateMessage "Файл '$File' младше $maxAgeDays дней ($($fileAgeDays.ToString('F1')) дней), пропускаем" "INFO"
                    }
                    return $false
                }
                else {
                    Write-LogRotateMessage "Файл '$File' старше $maxAgeDays дней ($($fileAgeDays.ToString('F1')) дней), будет обработан" "INFO"
                    return $true
                }
            }
        }
        catch {
            Write-LogRotateMessage "Ошибка при обработке параметра 'maxage': $_" "WARNING"
        }
    }
    
    if ($Force) {
        Write-LogRotateMessage "Файл '$File' будет обработан (Force = true)" "INFO"
        return $true
    }
    
    # Проверка на основе размера файла
    if ($Config.size -ne $null) {
        try {
            $sizeValue = $Config.size -replace "[kKmMgG]$", ""
            $sizeUnit = $Config.size -replace "^[0-9]+", ""
            
            $sizeValue = $sizeValue -replace "[^0-9]", ""
            if ([string]::IsNullOrEmpty($sizeValue)) { $sizeValue = "0" }
            
            $sizeBytes = [long]$sizeValue
            
            switch ($sizeUnit.ToUpper()) {
                "K" { $sizeBytes *= 1KB }
                "M" { $sizeBytes *= 1MB }
                "G" { $sizeBytes *= 1GB }
            }
            
            if ($fileInfo.Length -ge $sizeBytes) {
                return $true
            }
        }
        catch {
            Write-LogRotateMessage "Ошибка при обработке параметра 'size': $_" "WARNING"
        }
    }
    
    # Проверка на основе времени
    if ($lastRotationTime -ne $null) {
        $timespan = New-TimeSpan -Start $lastRotationTime -End (Get-Date)
        
        if ($Config.daily -and $timespan.TotalDays -ge 1) {
            return $true
        }
        
        if ($Config.weekly -and $timespan.TotalDays -ge 7) {
            return $true
        }
        
        if ($Config.monthly -and (
                (Get-Date).Month -ne $lastRotationTime.Month -or
                (Get-Date).Year -ne $lastRotationTime.Year)) {
            return $true
        }
        
        if ($Config.yearly -and (Get-Date).Year -ne $lastRotationTime.Year) {
            return $true
        }
    }
    
    return $false
}

function Invoke-LogRotate {
    param (
        [string]$File,
        [PSCustomObject]$Config,
        [hashtable]$StateData
    )
    
    if (-not (Test-Path $File)) {
        Write-LogRotateMessage "Файл '$File' не найден. Пропускаем." "WARNING"
        return
    }
    
    Write-LogRotateMessage "Ротация файла: $File" "INFO"
    
    $directory = Split-Path -Parent $File
    $fileName = Split-Path -Leaf $File
    
    $rotate = 5
    if ($Config.rotate -ne $null) {
        try {
            $rotateValue = $Config.rotate -replace "[^0-9]", ""
            if (-not [string]::IsNullOrEmpty($rotateValue)) {
                $rotate = [int]$rotateValue
            }
        } catch {
            Write-LogRotateMessage "Ошибка при обработке параметра 'rotate'. Используем значение по умолчанию: $rotate" "WARNING"
        }
    }
    
    $compress = if ($Config.compress -ne $null) { $Config.compress } else { $false }
    $compressCmd = if ($Config.compresscmd -ne $null) { $Config.compresscmd } else { "Compress-Archive" }
    $compressExt = if ($Config.compressext -ne $null) { $Config.compressext } else { ".zip" }
    
    $archiveDir = $directory
    if ($Config.olddir -ne $null) {
        $olddir = $Config.olddir.ToString().Trim()
        
        if (-not (Test-Path $olddir)) {
            try {
                New-Item -Path $olddir -ItemType Directory -Force | Out-Null
                Write-LogRotateMessage "Создана директория для архивов: $olddir" "INFO"
                $archiveDir = $olddir
            }
            catch {
                Write-LogRotateMessage "Ошибка при создании директории для архивов '$olddir': $_" "ERROR"
                $archiveDir = $directory
            }
        } else {
            $archiveDir = $olddir
            Write-LogRotateMessage "Используется существующая директория для архивов: $olddir" "INFO"
        }
    }
    
    if (-not (Test-Path $archiveDir)) {
        Write-LogRotateMessage "Директория для архивов недоступна, используем исходную директорию: $directory" "WARNING"
        $archiveDir = $directory
    }
    
    $prerotateScript = $null
    if ($Config.prerotate -ne $null) {
        if ($Config.prerotate -is [bool]) {
            $prerotateScript = $null
        } else {
            $prerotateScript = $Config.prerotate.ToString()
        }
    }
    
    $postrotateScript = $null
    if ($Config.postrotate -ne $null) {
        if ($Config.postrotate -is [bool]) {
            $postrotateScript = $null
        } else {
            $postrotateScript = $Config.postrotate.ToString()
        }
    }
    
    if ($prerotateScript -ne $null -and -not $Test) {
        Write-LogRotateMessage "Выполнение prerotate команд" "INFO"
        try {
            Invoke-Expression $prerotateScript
        }
        catch {
            Write-LogRotateMessage "Ошибка при выполнении prerotate: $_" "ERROR"
        }
    }
    
    if (-not $Test) {
        $oldestFile = Join-Path -Path $archiveDir -ChildPath "$fileName.$rotate"
        if ($compress) { $oldestFile += $compressExt }
        
        if (Test-Path $oldestFile) {
            Remove-Item $oldestFile -Force
            Write-LogRotateMessage "Удален устаревший файл: $oldestFile" "INFO"
        }
        
        for ($i = $rotate - 1; $i -ge 1; $i--) {
            $currentFile = Join-Path -Path $archiveDir -ChildPath "$fileName.$i"
            $nextFile = Join-Path -Path $archiveDir -ChildPath "$fileName.$($i + 1)"
            
            if ($compress) { $currentFile += $compressExt }
            if ($compress) { $nextFile += $compressExt }
            
            if (Test-Path $currentFile) {
                Move-Item $currentFile $nextFile -Force
                Write-LogRotateMessage "Перемещен файл: $currentFile -> $nextFile" "INFO"
            }
        }
        
        $newFile = Join-Path -Path $archiveDir -ChildPath "$fileName.1"
        
        $fileLocked = Test-FileLocked -FilePath $File
        if ($fileLocked) {
            Write-LogRotateMessage "Файл '$File' заблокирован другим процессом и будет пропущен" "WARNING"
            return
        }

        $copySuccess = $false
        $removeSuccess = $false

        if ($compress) {
            try {
                if ($compressCmd -eq "Compress-Archive") {
                    Compress-Archive -Path $File -DestinationPath "$newFile$compressExt" -Force
                    Write-LogRotateMessage "Создан архив: $newFile$compressExt" "INFO"
                    $copySuccess = $true
                }
                else {
                    Invoke-Expression "$compressCmd $File $newFile$compressExt"
                    Write-LogRotateMessage "Создан архив с пользовательской командой: $newFile$compressExt" "INFO"
                    $copySuccess = $true
                }
            }
            catch {
                Write-LogRotateMessage "Ошибка при создании архива: $_" "ERROR"
                
                if ($_.Exception.Message -like "*доступе*" -or 
                    $_.Exception.Message -like "*access*" -or 
                    $_.Exception.Message -like "*busy*" -or 
                    $_.Exception.Message -like "*занят*") {
                    Write-LogRotateMessage "Файл '$File', вероятно, занят системным процессом и будет пропущен" "WARNING"
                }
            }
        }
        else {
            try {
                Copy-Item $File $newFile -Force
                Write-LogRotateMessage "Скопирован файл: $File -> $newFile" "INFO"
                $copySuccess = $true
            }
            catch {
                Write-LogRotateMessage "Ошибка при копировании файла: $_" "ERROR"
                
                if ($_.Exception.Message -like "*доступе*" -or 
                    $_.Exception.Message -like "*access*" -or 
                    $_.Exception.Message -like "*busy*" -or 
                    $_.Exception.Message -like "*занят*") {
                    Write-LogRotateMessage "Файл '$File', вероятно, занят системным процессом и будет пропущен" "WARNING"
                }
            }
        }
        
        if ($copySuccess) {
            if ($Config.copytruncate) {
                try {
                    Clear-Content $File
                    Write-LogRotateMessage "Очищен файл: $File" "INFO"
                    $removeSuccess = $true
                } 
                catch {
                    Write-LogRotateMessage "Ошибка при очистке файла: $_" "ERROR"
                    
                    if ($_.Exception.Message -like "*доступе*" -or 
                        $_.Exception.Message -like "*access*" -or 
                        $_.Exception.Message -like "*busy*" -or 
                        $_.Exception.Message -like "*занят*") {
                        Write-LogRotateMessage "Файл '$File', вероятно, занят системным процессом" "WARNING"
                    }
                }
            }
            else {
                try {
                    Remove-Item $File -Force
                    Write-LogRotateMessage "Удален файл: $File" "INFO"
                    $removeSuccess = $true
                    
                    if ($Config.create -ne $null -and $Config.create -ne $false) {
                        try {
                            New-Item $File -ItemType File -Force | Out-Null
                            Write-LogRotateMessage "Создан новый пустой файл: $File" "INFO"
                            
                            if ($Config.mode -ne $null) {
                                $acl = Get-Acl $File
                                if ($Config.owner -ne $null -or $Config.group -ne $null) {
                                }
                                Set-Acl $File $acl
                            }
                        }
                        catch {
                            Write-LogRotateMessage "Ошибка при создании нового файла: $_" "ERROR"
                        }
                    }
                }
                catch {
                    Write-LogRotateMessage "Ошибка при удалении файла: $_" "ERROR"
                    
                    if ($_.Exception.Message -like "*доступе*" -or 
                        $_.Exception.Message -like "*access*" -or 
                        $_.Exception.Message -like "*busy*" -or 
                        $_.Exception.Message -like "*занят*") {
                        Write-LogRotateMessage "Файл '$File', вероятно, занят системным процессом" "WARNING"
                    }
                }
            }
        }
    }
    
    $rotationSuccess = $copySuccess -and $removeSuccess
    if ($postrotateScript -ne $null -and -not $Test -and $rotationSuccess) {
        Write-LogRotateMessage "Выполнение postrotate команд" "INFO"
        try {
            Invoke-Expression $postrotateScript
        }
        catch {
            Write-LogRotateMessage "Ошибка при выполнении postrotate: $_" "ERROR"
        }
    }
    
    if (-not $Test) {
        if ($rotationSuccess) {
            if (-not $StateData.ContainsKey($File)) {
                $StateData[$File] = @{}
            }
            $StateData[$File].lastRotation = (Get-Date).ToString("o")
            Write-LogRotateMessage "Ротация файла '$File' завершена успешно" "SUCCESS"
        } else {
            Write-LogRotateMessage "Ротация файла '$File' не выполнена из-за ошибок доступа" "WARNING"
        }
    }
}

function Parse-LogRotateConfig {
    param (
        [string]$ConfigFile
    )
    
    if (-not (Test-Path $ConfigFile)) {
        Write-LogRotateMessage "Конфигурационный файл '$ConfigFile' не найден" "ERROR"
        exit 1
    }
    
    try {
        $content = Get-Content $ConfigFile -Raw -Encoding UTF8
    }
    catch {
        try {
            $content = Get-Content $ConfigFile -Raw
        }
        catch {
            Write-LogRotateMessage "Ошибка при чтении файла '$ConfigFile': $_" "ERROR"
            exit 1
        }
    }
    
    $content = $content -replace "#.*$", "" -replace "//.*$", ""
    
    $globalConfig = @{}
    
    $includeRegex = [regex]'include\s+(.+)'
    $matches = $includeRegex.Matches($content)
    
    foreach ($match in $matches) {
        $includePath = $match.Groups[1].Value.Trim()
        if (Test-Path $includePath) {
            $includeFiles = Get-Item $includePath
            foreach ($file in $includeFiles) {
                Parse-LogRotateConfig -ConfigFile $file.FullName
            }
        }
    }
    
    $sections = @()
    $currentSection = $null
    $inSection = $false
    $openBraces = 0
    
    $lines = $content -split "`n"
    $sectionRegex = [regex]'^(.+?)\s*\{'
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ($line -eq "") { continue }
        
        if (-not $inSection) {
            $match = $sectionRegex.Match($line)
            if ($match.Success) {
                $inSection = $true
                
                $filesPattern = $match.Groups[1].Value.Trim()
                $filesPattern = $filesPattern -replace '^"(.*)"$', '$1' -replace "^'(.*)'$", '$1'
                
                $currentSection = @{
                    files = $filesPattern -split "\s+"
                    config = @{}
                }
                $openBraces = 1
                
                if ($line.Contains("}")) {
                    $openBraces--
                }
            }
            else {
                $parts = $line -split "\s+", 2
                $directive = $parts[0].Trim()
                
                if ($parts.Length -gt 1) { 
                    $value = $parts[1].Trim() -replace "#.*$", "" -replace "//.*$", ""
                    $value = $value.Trim()
                } else { 
                    $value = $true 
                }
                
                if ($directive -ne "include") {
                    $globalConfig[$directive] = $value
                }
            }
        }
        else {
            $openBraces += ($line.ToCharArray() | Where-Object { $_ -eq '{' }).Count
            $openBraces -= ($line.ToCharArray() | Where-Object { $_ -eq '}' }).Count
            
            if ($openBraces -eq 0) {
                $inSection = $false
                $sections += $currentSection
                $currentSection = $null
            }
            else {
                $parts = $line -split "\s+", 2
                $directive = $parts[0].Trim()
                
                if ($directive -ne "{" -and $directive -ne "}") {
                    if ($parts.Length -gt 1) { 
                        $value = $parts[1].Trim() -replace "#.*$", "" -replace "//.*$", ""
                        $value = $value.Trim()
                    } else { 
                        $value = $true 
                    }
                    
                    $currentSection.config[$directive] = $value
                }
            }
        }
    }
    
    foreach ($section in $sections) {
        foreach ($key in $globalConfig.Keys) {
            if (-not $section.config.ContainsKey($key)) {
                $section.config[$key] = $globalConfig[$key]
            }
        }
    }
    
    return $sections
}

#endregion

# Основная логика
try {
    $stateData = Get-StateData
    
    Write-LogRotateMessage "Обработка конфигурационного файла: $ConfigFile" "INFO"
    $config = Parse-LogRotateConfig -ConfigFile $ConfigFile
    
    Write-LogRotateMessage "Найдено секций конфигурации: $($config.Count)" "INFO"
    
    $processedFilesCount = 0
    $skippedFilesCount = 0
    
    foreach ($section in $config) {
        $filePatterns = $section.files
        $sectionConfig = $section.config
        
        Write-LogRotateMessage "Обработка шаблонов файлов: $($filePatterns -join ', ')" "INFO"
        
        foreach ($pattern in $filePatterns) {
            $files = @()
            $originalFiles = @()
            
            $pattern = $pattern -replace '^"(.*)"$', '$1' -replace "^'(.*)'$", '$1'
            
            Write-LogRotateMessage "Поиск файлов по шаблону: $pattern" "INFO"
            
            try {
                if ($pattern -like "*/*" -or $pattern -like "*\*") {
                    $recurse = $sectionConfig.recurse -ne $null
                    if ($recurse) {
                        Write-LogRotateMessage "Используется рекурсивный поиск для: $pattern" "INFO"
                        $originalFiles = Get-ChildItem -Path $pattern -File -Recurse -ErrorAction SilentlyContinue
                    } else {
                        $originalFiles = Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue
                    }
                    
                    if ($originalFiles.Count -gt 0) {
                        Write-LogRotateMessage "Всего найдено файлов: $($originalFiles.Count)" "INFO"
                        $files = $originalFiles
                    } else {
                        Write-LogRotateMessage "Файлы не найдены по шаблону: $pattern" "INFO"
                        continue
                    }
                    
                    if ($sectionConfig.exclude -ne $null) {
                        $excludePatterns = $sectionConfig.exclude -split "\s+"
                        $excludedFiles = @()
                        
                        foreach ($excludePattern in $excludePatterns) {
                            $excludePattern = $excludePattern -replace '^"(.*)"$', '$1' -replace "^'(.*)'$", '$1'
                            Write-LogRotateMessage "Применение исключения: $excludePattern" "INFO"
                            
                            $filesToExclude = $files | Where-Object { 
                                $_.FullName -like $excludePattern -or 
                                $_.DirectoryName -like $excludePattern -or
                                $_.FullName -like "$excludePattern\*"
                            }
                            
                            $excludedFiles += $filesToExclude
                        }
                        
                        if ($excludedFiles.Count -gt 0) {
                            $files = $files | Where-Object { $excludedFiles -notcontains $_ }
                            Write-LogRotateMessage "Исключено файлов: $($excludedFiles.Count)" "INFO"
                            Write-LogRotateMessage "Осталось для обработки: $($files.Count)" "INFO"
                        }
                    }
                }
                else {
                    if (Test-Path $pattern -PathType Leaf) {
                        $files = @(Get-Item $pattern)
                        Write-LogRotateMessage "Найден один конкретный файл: $pattern" "INFO"
                    } else {
                        Write-LogRotateMessage "Файл не найден: $pattern" "INFO"
                        continue
                    }
                }
                
                $filesForProcessing = 0
                foreach ($file in $files) {
                    $filePath = $file.FullName
                    
                    $shouldRotate = Test-ShouldRotate -File $filePath -Config $sectionConfig -StateData $stateData
                    if ($shouldRotate) {
                        $filesForProcessing++
                        if ($Test) {
                            Write-LogRotateMessage "Тестовый режим: файл '$filePath' будет обработан" "TEST"
                        }
                        else {
                            Invoke-LogRotate -File $filePath -Config $sectionConfig -StateData $stateData
                            $processedFilesCount++
                        }
                    } else {
                        $skippedFilesCount++
                    }
                }
                
                Write-LogRotateMessage "Подготовлено к обработке: $filesForProcessing файлов" "INFO"
            }
            catch {
                Write-LogRotateMessage "Ошибка при поиске файлов по шаблону '$pattern': $_" "ERROR"
            }
        }
    }
    
    if (-not $Test) {
        Save-StateData -StateData $stateData
    }
    
    if ($Test) {
        Write-LogRotateMessage "Задача logrotate завершена успешно в тестовом режиме. Не обработано файлов: $skippedFilesCount" "SUCCESS"
    } else {
        Write-LogRotateMessage "Задача logrotate завершена успешно. Обработано файлов: $processedFilesCount, пропущено: $skippedFilesCount" "SUCCESS"
    }
}
catch {
    Write-LogRotateMessage "Произошла ошибка: $_" "ERROR"
    exit 1
} 