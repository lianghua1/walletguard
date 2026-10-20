#requires -Version 5.1
# WalletGuard.ps1 - Agent Harness 中转站注入风险自检（只读）
# 先选 harness，再检查：模型链路 / 钱包链路 / 注入闸门 / 损失上限
# 不读取、不打印、不上传任何 cookie / 密钥。
param(
    [switch]$NoOpen,
    [switch]$Unicode,
    [string]$Harness = ''
)

$ErrorActionPreference = 'SilentlyContinue'
$Colors = @{ OK='Green'; Warn='Yellow'; Bad='Red'; Info='Cyan'; Dim='DarkGray'; Plain='White'; Accent='Magenta' }
$script:nBad = 0; $script:nWarn = 0

$chH = '-'; $chV = '|'; $chC = '+'
if ($Unicode) { $chH = [string][char]0x2500; $chV = [string][char]0x2502; $chC = [string][char]0x253C }

$isWin = ($env:OS -eq 'Windows_NT')
$isMac = ((-not $isWin) -and (Test-Path '/System/Library'))
$HomeDir = if ($env:USERPROFILE) { $env:USERPROFILE } else { $env:HOME }
if (-not ($isWin -or $isMac)) { Write-Host 'WalletGuard 支持 Windows / macOS。' -ForegroundColor Yellow; exit 1 }

$Width = 68
try { $cw = $Host.UI.RawUI.WindowSize.Width; if ($cw -gt 20) { $Width = [Math]::Min(68, [Math]::Max(50, $cw - 2)) } } catch { }

if ($isWin) {
  try {
    Add-Type -Namespace WG -Name Con -ErrorAction Stop -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetStdHandle(int n);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool GetConsoleMode(System.IntPtr h, out uint m);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool SetConsoleMode(System.IntPtr h, uint m);
"@
    $hIn = [WG.Con]::GetStdHandle(-10); $m = 0
    if ([WG.Con]::GetConsoleMode($hIn, [ref]$m)) { [void][WG.Con]::SetConsoleMode($hIn, (($m -band (-bnot 0x0040)) -bor 0x0080)) }
  } catch { }
}

function Get-DisplayWidth($s) {
    $w = 0
    foreach ($ch in ([string]$s).ToCharArray()) {
        $c = [int]$ch
        if (($c -ge 0x1100 -and $c -le 0x115F) -or ($c -ge 0x2E80 -and $c -le 0xA4CF) -or ($c -ge 0xAC00 -and $c -le 0xD7A3) -or
            ($c -ge 0xF900 -and $c -le 0xFAFF) -or ($c -ge 0xFE30 -and $c -le 0xFE6F) -or ($c -ge 0xFF00 -and $c -le 0xFF60) -or
            ($c -ge 0xFFE0 -and $c -le 0xFFE6)) { $w += 2 } else { $w += 1 }
    }
    return $w
}

$out = New-Object System.Collections.ArrayList
function Add-Line($text, $level = 'Plain') { [void]$out.Add(@{ t = [string]$text; c = $level }) }
function Box($text) { Add-Line ($chV + ' ' + $text + (' ' * [Math]::Max(0, $Width - 3 - (Get-DisplayWidth $text))) + $chV) 'Info' }
function Section($n, $title) {
    Add-Line '' 'Plain'
    $prefix = ' ' + $n + '  ' + $title + ' '
    Add-Line ($prefix + ($chH * [Math]::Max(0, $Width - (Get-DisplayWidth $prefix)))) 'Info'
}
function Tag($level) { switch ($level) { 'Bad' { 'HIGH' } 'Warn' { 'WARN' } default { ' OK ' } } }
function Row($label, $value, $level = 'Plain') {
    if ($level -eq 'Bad') { $script:nBad++ } elseif ($level -eq 'Warn') { $script:nWarn++ }
    $pad1 = [Math]::Max(2, 26 - (Get-DisplayWidth $label))
    $pad2 = [Math]::Max(2, 28 - (Get-DisplayWidth $value))
    if ($level -eq 'Dim') { Add-Line ('  ' + $label + (' ' * $pad1) + $value) 'Dim' }
    else { Add-Line ('  ' + $label + (' ' * $pad1) + $value + (' ' * $pad2) + (Tag $level)) $level }
}
function Note($t) { Add-Line ('     ' + $t) 'Dim' }

function Invoke-BawJson($argList, $timeoutSec = 45) {
    $job = $null
    try { $job = Start-Job -ScriptBlock { param($a) $ErrorActionPreference='SilentlyContinue'; & baw @a 2>$null } -ArgumentList (,$argList) } catch { }
    if (-not $job) { try { $raw = & baw @argList 2>$null; return ($raw | Out-String | ConvertFrom-Json) } catch { return $null } }
    $done = Wait-Job $job -Timeout $timeoutSec
    if ($done) { $raw = Receive-Job $job } else { Stop-Job $job -ErrorAction SilentlyContinue; $raw = $null }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    if (-not $raw) { return $null }
    try { return ($raw | Out-String | ConvertFrom-Json) } catch { return $null }
}

function Get-TlsIssuer($target) {
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $ar = $tcp.BeginConnect($target, 443, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(6000)) { return $null }
        $tcp.EndConnect($ar)
        $cb = [Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) return $true }
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $cb)
        $ssl.AuthenticateAsClient($target)
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $issuer = $cert.Issuer
        $ssl.Dispose(); $tcp.Close()
        return $issuer
    } catch { return $null }
}

# ---------------- Harness 注册表 ----------------
$Known = @(
    @{ Id='dsh';    Name='DeepSeek Harness'; Path=(Join-Path $HomeDir '.dsh') },
    @{ Id='codex';  Name='Codex CLI';        Path=(Join-Path $HomeDir '.codex') },
    @{ Id='claude'; Name='Claude Code';      Path=(Join-Path $HomeDir '.claude') },
    @{ Id='gemini'; Name='Gemini CLI';       Path=(Join-Path $HomeDir '.gemini') },
    @{ Id='qwen';   Name='Qwen Code';        Path=(Join-Path $HomeDir '.qwen') },
    @{ Id='opencode'; Name='OpenCode';       Path=(Join-Path $HomeDir '.config/opencode') },
    @{ Id='cursor'; Name='Cursor';           Path=$(if ($env:APPDATA) { Join-Path $env:APPDATA 'Cursor' } else { Join-Path $HomeDir 'Library/Application Support/Cursor' }) }
)
$detected = @($Known | Where-Object { Test-Path $_.Path })

$selected = @()
if ($Harness) {
    if ($Harness -eq 'all') { $selected = $detected }
    else { $selected = @($detected | Where-Object { $_.Id -eq $Harness -or $_.Name -like ('*' + $Harness + '*') }) }
    if ($selected.Count -eq 0) {
        Write-Host ('未找到 harness: ' + $Harness) -ForegroundColor Yellow
        Write-Host ('可用: ' + (($detected | ForEach-Object { $_.Id }) -join ', ')) -ForegroundColor Yellow
        exit 1
    }
} else {
    if ($detected.Count -eq 0) { $selected = @() }
    elseif ($detected.Count -eq 1) { $selected = $detected }
    else {
        Write-Host ''
        Write-Host ' 检测到多个 Agent Harness，请选择要检查的对象:' -ForegroundColor Cyan
        for ($i = 0; $i -lt $detected.Count; $i++) {
            Write-Host ('   [{0}] {1}   {2}' -f ($i + 1), $detected[$i].Name, $detected[$i].Path) -ForegroundColor White
        }
        Write-Host '   [a] 全部' -ForegroundColor DarkGray
        $sel = $null
        try { $sel = Read-Host ' 输入编号后回车（直接回车=全部）' } catch { $sel = 'a' }
        if (-not $sel) { $sel = 'a' }
        if ($sel -eq 'a') { $selected = $detected }
        else {
            $idx = 0
            if ([int]::TryParse($sel, [ref]$idx) -and $idx -ge 1 -and $idx -le $detected.Count) { $selected = @($detected[$idx - 1]) }
            else { $selected = $detected }
        }
    }
}

# ---------------- 采集函数 ----------------
function Get-Endpoints($h) {
    $res = @()
    if ($h.Id -eq 'dsh') {
        $profiles = Join-Path $h.Path 'profiles'
        if (Test-Path $profiles) {
            Get-ChildItem $profiles -Recurse -Filter 'cordis.patch.yml' -ErrorAction SilentlyContinue | ForEach-Object {
                Select-String -Path $_.FullName -Pattern '^\s*baseURL:\s*(\S+)' -ErrorAction SilentlyContinue | ForEach-Object {
                    $u = $_.Matches[0].Groups[1].Value.Trim('"', "'")
                    if ($res -notcontains $u) { $res += $u }
                }
            }
        }
        return $res
    }
    # 通用：在配置目录里找 base_url / baseURL / api_base
    $files = Get-ChildItem $h.Path -Recurse -File -Depth 2 -ErrorAction SilentlyContinue |
             Where-Object { $_.Length -lt 2MB -and $_.Extension -in '.json', '.toml', '.yaml', '.yml', '.conf', '.ini' } |
             Select-Object -First 40
    foreach ($f in $files) {
        Select-String -Path $f.FullName -Pattern '(base_?url|api_?base|baseURL)\s*[:=]\s*[''"]?([^''"\s,}]+)' -ErrorAction SilentlyContinue | ForEach-Object {
            $u = $_.Matches[0].Groups[2].Value.Trim()
            if ($u -match '^https?://' -and $res -notcontains $u) { $res += $u }
        }
    }
    return $res
}

function Get-Gate($h) {
    $g = @{ approval = $null; sandbox = $null; source = ''; mixed = @() }
    if ($h.Id -eq 'dsh') {
        $sessDir = Join-Path $h.Path 'storages\session_projcache\sessions'
        if (-not (Test-Path $sessDir)) { return $g }
        $recs = New-Object System.Collections.ArrayList
        $files = Get-ChildItem $sessDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 5MB } | Sort-Object LastWriteTime -Descending | Select-Object -First 200
        foreach ($f in $files) {
            if ($recs.Count -ge 5) { break }
            $mm = Select-String -Path $f.FullName -Pattern '"approval"\s*:\s*"([^"]+)"' -ErrorAction SilentlyContinue | Select-Object -Last 1
            if (-not $mm) { continue }
            $ss = Select-String -Path $f.FullName -Pattern '"sandbox"\s*:\s*"([^"]+)"' -ErrorAction SilentlyContinue | Select-Object -Last 1
            [void]$recs.Add(@{
                a = $mm.Matches[0].Groups[1].Value
                s = if ($ss) { $ss.Matches[0].Groups[1].Value } else { '?' }
                t = $f.LastWriteTime
            })
        }
        if ($recs.Count -gt 0) {
            $g.approval = $recs[0].a; $g.sandbox = $recs[0].s
            $g.source = '会话记录 ' + $recs[0].t.ToString('HH:mm:ss')
            $g.mixed = @($recs | ForEach-Object { $_.a + '/' + $_.s } | Sort-Object -Unique)
        }
        return $g
    }
    # 通用：从配置文件里抓审批/沙箱相关的键
    $files = Get-ChildItem $h.Path -Recurse -File -Depth 2 -ErrorAction SilentlyContinue |
             Where-Object { $_.Length -lt 2MB -and $_.Extension -in '.json', '.toml', '.yaml', '.yml', '.conf', '.ini' } |
             Select-Object -First 40
    foreach ($f in $files) {
        if (-not $g.approval) {
            $am = Select-String -Path $f.FullName -Pattern '(approval_policy|approvalMode|approval_mode|defaultMode|autoAccept|bypassPermissions|dangerouslySkipPermissions)\s*[:=]\s*[''"]?([^''"\s,}]+)' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($am) { $g.approval = $am.Matches[0].Groups[2].Value; $g.source = $f.Name }
        }
        if (-not $g.sandbox) {
            $sm = Select-String -Path $f.FullName -Pattern '(sandbox_mode|sandboxMode|sandbox)\s*[:=]\s*[''"]?([^''"\s,}]+)' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sm) { $g.sandbox = $sm.Matches[0].Groups[2].Value }
        }
    }
    return $g
}

function Test-NoConfirm($appr) {
    if (-not $appr) { return $null }
    return ($appr -match '^(never|bypassPermissions|yolo|dangerously-skip|danger-full-access)$')
}

$verdict = New-Object System.Collections.ArrayList
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm'

Add-Line ($chC + ($chH * ($Width - 2)) + $chC) 'Dim'
Box 'WalletGuard  |  中转站注入风险自检'
Box ($stamp + '  |  只读  |  先选 harness 再检查')
Add-Line ($chC + ($chH * ($Width - 2)) + $chC) 'Dim'

# ---------------- 0 ----------------
Section '0' '已选 Harness'
if ($selected.Count -eq 0) {
    Row 'harness' '未检测到任何已知 harness' 'Warn'
    Note ('已查找: ' + (($Known | ForEach-Object { $_.Path }) -join ' | '))
} else {
    foreach ($h in $selected) { Row $h.Name (Split-Path $h.Path -Leaf) 'Dim' }
    Note ('总计 ' + $selected.Count + ' 个；可用 -Harness <id> 指定，id: ' + (($Known | ForEach-Object { $_.Id }) -join ', '))
}

# ---------------- 1 ----------------
Section '1' '模型链路'
$anyThird = $false
foreach ($h in $selected) {
    $eps = @(Get-Endpoints $h)
    if ($eps.Count -eq 0) { Row $h.Name '未发现端点配置' 'Dim'; continue }
    foreach ($u in $eps) {
        $host_ = $null; try { $host_ = ([uri]$u).Host } catch { }
        if (-not $host_) { Row $h.Name $u 'Warn'; continue }
        $official = $host_ -match '(^|\.)(deepseek\.com|anthropic\.com|openai\.com|googleapis\.com|githubcopilot\.com)$'
        Row $h.Name $host_ $(if ($official) { 'OK' } else { 'Bad' })
        if (-not $official) { $anyThird = $true; [void]$verdict.Add($h.Name + ' 的模型流量经过第三方中转 ' + $host_) }
    }
}
$relayEnv = @()
foreach ($v in 'OPENAI_BASE_URL','ANTHROPIC_BASE_URL','DEEPSEEK_BASE_URL','OPENAI_API_BASE','GEMINI_API_BASE') {
    $val = [Environment]::GetEnvironmentVariable($v)
    if ($val) { $relayEnv += "$v=$val" }
}
if ($relayEnv.Count -gt 0) {
    Row '环境变量改道' '发现' 'Bad'
    foreach ($e in $relayEnv) { Note $e }
    [void]$verdict.Add('环境变量指定了模型端点：影响所有继承该环境的进程')
} else { Row '环境变量改道' '未发现' 'OK' }

# ---------------- 2 ----------------
Section '2' '钱包链路完整性'
$redirect = @()
foreach ($v in 'WALLET_API_URL','BINANCE_BAW_DIR') {
    $val = [Environment]::GetEnvironmentVariable($v); if ($val) { $redirect += "$v=$val" }
}
if ($redirect.Count -gt 0) {
    Row 'API/目录改道' '发现' 'Bad'
    foreach ($r in $redirect) { Note $r }
    [void]$verdict.Add('环境变量可改变钱包 API 基址或状态目录')
} else { Row 'API/目录改道' '未发现' 'OK' }

$proxy = @()
foreach ($v in 'HTTPS_PROXY','HTTP_PROXY','ALL_PROXY','NODE_EXTRA_CA_CERTS') {
    $val = [Environment]::GetEnvironmentVariable($v); if ($val) { $proxy += "$v=$val" }
}
if ($proxy.Count -gt 0) {
    Row '代理/自定义 CA' '发现' 'Warn'
    foreach ($x in $proxy) { Note $x }
    [void]$verdict.Add('存在代理或自定义根证书：出网链路可被观察/改写')
} else { Row '代理/自定义 CA' '未发现' 'OK' }

$tlsOff = ([Environment]::GetEnvironmentVariable('NODE_TLS_REJECT_UNAUTHORIZED') -eq '0')
Row 'TLS 校验关闭' $(if ($tlsOff) { '是' } else { '否' }) $(if ($tlsOff) { 'Bad' } else { 'OK' })
if ($tlsOff) { [void]$verdict.Add('NODE_TLS_REJECT_UNAUTHORIZED=0：中间人可伪装成币安') }

$hostsPath = if ($isWin) { Join-Path $env:SystemRoot 'System32\drivers\etc\hosts' } else { '/etc/hosts' }
$hostsHit = @(Select-String -Path $hostsPath -Pattern 'binance|deepseek|github' -ErrorAction SilentlyContinue)
if ($hostsHit.Count -gt 0) {
    Row 'hosts 劫持' '发现相关条目' 'Bad'
    foreach ($hh in $hostsHit) { Note $hh.Line.Trim() }
    [void]$verdict.Add('hosts 文件里有相关域名条目')
} else { Row 'hosts 劫持' '未发现' 'OK' }

$dns = @()
if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    $dns = @(Resolve-DnsName 'www.binance.com' -Type A -ErrorAction SilentlyContinue | Where-Object IPAddress | Select-Object -ExpandProperty IPAddress)
} else {
    try { $dns = @([System.Net.Dns]::GetHostAddresses('www.binance.com') | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }) } catch { }
}
$dnsTxt = if ($dns.Count -gt 0) { $dns -join ', ' } else { '解析失败' }
$isPrivate = $false; $isFakeIp = $false
foreach ($ip in $dns) {
    if ($ip -match '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { $isPrivate = $true }
    if ($ip -match '^198\.1[89]\.') { $isFakeIp = $true }
}
Row 'DNS(www.binance.com)' $dnsTxt $(if ($isPrivate) { 'Bad' } elseif ($isFakeIp) { 'Warn' } else { 'OK' })
if ($isPrivate) { [void]$verdict.Add('币安域名解析到内网/本机地址') }
elseif ($isFakeIp) { Note '198.18.0.0/15 是本机代理 fake-ip，流量经代理接管' }

$issuer = Get-TlsIssuer 'www.binance.com'
$knownCa = '(DigiCert|Let.s Encrypt|GlobalSign|Sectigo|Amazon|Cloudflare|Google Trust|Entrust|GeoTrust|GoDaddy|Microsoft|IdenTrust|Certum|SSL\.com|ZeroSSL|HARICA|Actalis|Buypass|Apple)'
if (-not $issuer) { Row 'TLS 签发者' '获取失败' 'Warn' }
else {
    $ok = $issuer -match $knownCa
    Row 'TLS 签发者' $(if ($ok) { '公共 CA' } else { '非公共 CA' }) $(if ($ok) { 'OK' } else { 'Bad' })
    $iss = ($issuer -replace '\s+', ' '); if ($iss.Length -gt 56) { $iss = $iss.Substring(0, 56) + '...' }
    Note $iss
    if (-not $ok) { [void]$verdict.Add('币安站点证书由非公共 CA 签发：存在 TLS 中间人') }
}

# ---------------- 3 ----------------
Section '3' '注入闸门'
foreach ($h in $selected) {
    $g = Get-Gate $h
    if (-not $g.approval -and -not $g.sandbox) { Row $h.Name '未发现审批/沙箱配置' 'Dim'; continue }
    $noConfirm = Test-NoConfirm $g.approval
    Row ($h.Name + ' 审批') $(if ($g.approval) { $g.approval } else { '未配置(默认)' }) $(if ($noConfirm) { 'Bad' } elseif (-not $g.approval) { 'Warn' } else { 'OK' })
    if ($g.sandbox) { Row ($h.Name + ' 沙箱') $g.sandbox $(if ($g.sandbox -match 'danger') { 'Bad' } elseif ($g.sandbox -match 'workspace') { 'Warn' } else { 'OK' }) }
    if ($g.source) { Row ($h.Name + ' 来源') $g.source 'Dim' }
    if ($g.mixed -and $g.mixed.Count -gt 1) {
        Row ($h.Name + ' 一致性') ('不一致（' + $g.mixed.Count + ' 种）') 'Warn'
        Note ($g.mixed -join ' / ')
    }
    if ($noConfirm) {
        Row ($h.Name + ' 判定') '无确认，注入直接执行' 'Bad'
        [void]$verdict.Add($h.Name + '：审批=' + $g.approval + '，注入的工具调用无需确认')
    } else {
        Row ($h.Name + ' 判定') '需确认或已收紧' 'OK'
    }
}

# ---------------- 4 ----------------
Section '4' '损失上限'
$baw = Get-Command baw -ErrorAction SilentlyContinue
if (-not $baw) { Row 'baw CLI' '未安装' 'Dim' }
else {
    $st = Invoke-BawJson @('wallet','status','--json')
    if ($st -and $st.success) {
        $state = $st.data.status
        Row 'wallet status' $state $(if ($state -eq 'CONNECTED') { 'Warn' } else { 'OK' })
        if ($state -eq 'CONNECTED') {
            $set = Invoke-BawJson @('wallet','settings','--json')
            if ($set -and $set.success) {
                $d = $set.data
                Row '今日剩余额度' (([string]$d.quotaLeft) + ' / ' + ([string]$d.dailyLimit) + ' USD')
                $devOn = ($d.devMode -and $d.devMode.enabled)
                Row '开发者模式' $(if ($devOn) { '开启（可任意合约调用）' } else { '关闭' }) $(if ($devOn) { 'Bad' } else { 'OK' })
                Row '代币白名单' $(if ($d.tradeAllTokens) { '关闭' } else { '开启' }) $(if ($d.tradeAllTokens) { 'Bad' } else { 'OK' })
                Row '会话到期' ([string]$d.sessionExpireTime) 'Dim'
                if ($devOn) { [void]$verdict.Add('devMode 开启：注入后损失不再受转账额度限制') }
            } else { Row 'wallet settings' '查询失败或超时' 'Warn' }
        }
    } else { Row 'wallet status' '失败/超时/未登录' 'Warn' }
}

# ---------------- 结论 ----------------
Add-Line '' 'Plain'
$head = ' 结论  '
Add-Line ($head + ($chH * [Math]::Max(0, $Width - (Get-DisplayWidth $head)))) 'Accent'
if ($verdict.Count -eq 0) { Add-Line '  · 未发现中转/改道/无闸门等问题。' 'OK' }
else { foreach ($v in $verdict) { Add-Line ('  > ' + $v) 'Warn' } }
Add-Line '' 'Plain'
Add-Line (' 完成：' + $script:nBad + ' 项高危 / ' + $script:nWarn + ' 项注意') $(if ($script:nBad -gt 0) { 'Bad' } elseif ($script:nWarn -gt 0) { 'Warn' } else { 'OK' })
Note '范围仅限中转站相关风险；凭据存储、依赖链、服务端行为不在本检查内。'

$dest = [Environment]::GetFolderPath('Desktop'); if (-not $dest) { $dest = $env:USERPROFILE }
$logPath = Join-Path $dest 'WalletGuard-report.txt'
($out | ForEach-Object { $_.t }) | Set-Content -Path $logPath -Encoding UTF8
if (-not $NoOpen) {
    try {
        if ($isWin) { Start-Process notepad.exe -ArgumentList ('"' + $logPath + '"') }
        else { Start-Process 'open' -ArgumentList ('-a', 'TextEdit', $logPath) }
    } catch { }
}

Write-Host ''
foreach ($l in $out) { $col = if ($Colors.ContainsKey($l.c)) { $Colors[$l.c] } else { 'White' }; Write-Host $l.t -ForegroundColor $col }
Write-Host ''
Write-Host ('  报告: ' + $logPath) -ForegroundColor DarkGray
Write-Host ''