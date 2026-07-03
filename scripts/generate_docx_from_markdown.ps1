param(
    [Parameter(Mandatory = $true)]
    [string]$InputMarkdown,

    [Parameter(Mandatory = $true)]
    [string]$OutputDocx
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Escape-Html {
    param([string]$Text)

    if ($null -eq $Text) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Convert-InlineMarkup {
    param([string]$Text)

    $escaped = Escape-Html $Text
    $escaped = [regex]::Replace($escaped, '`([^`]+)`', '<code>$1</code>')
    $escaped = [regex]::Replace($escaped, '\*\*([^*]+)\*\*', '<strong>$1</strong>')
    return $escaped
}

function Convert-Table {
    param([System.Collections.Generic.List[string]]$Lines)

    if ($Lines.Count -lt 2) {
        return ''
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($line in $Lines) {
        $trimmed = $line.Trim()
        if (-not $trimmed.StartsWith('|')) {
            continue
        }

        $cells = $trimmed.Trim('|').Split('|') | ForEach-Object { $_.Trim() }
        $rows.Add($cells)
    }

    if ($rows.Count -lt 2) {
        return ''
    }

    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine('<table>')
    [void]$html.AppendLine('<thead><tr>')
    foreach ($cell in $rows[0]) {
        [void]$html.AppendLine("<th>$(Convert-InlineMarkup $cell)</th>")
    }
    [void]$html.AppendLine('</tr></thead>')
    [void]$html.AppendLine('<tbody>')

    for ($i = 2; $i -lt $rows.Count; $i++) {
        [void]$html.AppendLine('<tr>')
        foreach ($cell in $rows[$i]) {
            [void]$html.AppendLine("<td>$(Convert-InlineMarkup $cell)</td>")
        }
        [void]$html.AppendLine('</tr>')
    }

    [void]$html.AppendLine('</tbody></table>')
    return $html.ToString()
}

if (-not (Test-Path -LiteralPath $InputMarkdown)) {
    throw "Input file not found: $InputMarkdown"
}

$outputParent = Split-Path -Parent $OutputDocx
if (-not $outputParent) {
    throw 'Output path must include a parent directory.'
}
if (-not (Test-Path -LiteralPath $outputParent)) {
    throw "Output directory not found: $outputParent"
}

$lines = [System.IO.File]::ReadAllLines((Resolve-Path -LiteralPath $InputMarkdown), [System.Text.Encoding]::UTF8)

$html = New-Object System.Text.StringBuilder
[void]$html.AppendLine('<!DOCTYPE html>')
[void]$html.AppendLine('<html><head><meta charset="utf-8" />')
[void]$html.AppendLine('<style>')
[void]$html.AppendLine('body { font-family: Calibri, Arial, sans-serif; font-size: 11pt; line-height: 1.35; color: #111; margin: 28px; }')
[void]$html.AppendLine('h1, h2, h3 { color: #1f4e79; margin-top: 20px; margin-bottom: 8px; }')
[void]$html.AppendLine('h1 { font-size: 20pt; }')
[void]$html.AppendLine('h2 { font-size: 15pt; }')
[void]$html.AppendLine('h3 { font-size: 12.5pt; }')
[void]$html.AppendLine('p { margin: 0 0 10px 0; }')
[void]$html.AppendLine('ul, ol { margin-top: 0; margin-bottom: 10px; }')
[void]$html.AppendLine('table { border-collapse: collapse; width: 100%; margin: 10px 0 14px 0; }')
[void]$html.AppendLine('th, td { border: 1px solid #7f7f7f; padding: 6px 8px; vertical-align: top; }')
[void]$html.AppendLine('th { background: #d9e2f3; text-align: left; }')
[void]$html.AppendLine('pre { background: #f4f6f8; border: 1px solid #d0d7de; padding: 10px; white-space: pre-wrap; font-family: Consolas, "Courier New", monospace; font-size: 9.5pt; }')
[void]$html.AppendLine('code { font-family: Consolas, "Courier New", monospace; font-size: 9.5pt; }')
[void]$html.AppendLine('</style></head><body>')

$paragraphLines = New-Object System.Collections.Generic.List[string]
$unorderedItems = New-Object System.Collections.Generic.List[string]
$orderedItems = New-Object System.Collections.Generic.List[string]
$tableLines = New-Object System.Collections.Generic.List[string]
$codeLines = New-Object System.Collections.Generic.List[string]
$inCodeBlock = $false

function Flush-Paragraph {
    if ($paragraphLines.Count -gt 0) {
        $text = ($paragraphLines -join ' ').Trim()
        if ($text) {
            [void]$html.AppendLine("<p>$(Convert-InlineMarkup $text)</p>")
        }
        $paragraphLines.Clear()
    }
}

function Flush-UnorderedList {
    if ($unorderedItems.Count -gt 0) {
        [void]$html.AppendLine('<ul>')
        foreach ($item in $unorderedItems) {
            [void]$html.AppendLine("<li>$(Convert-InlineMarkup $item)</li>")
        }
        [void]$html.AppendLine('</ul>')
        $unorderedItems.Clear()
    }
}

function Flush-OrderedList {
    if ($orderedItems.Count -gt 0) {
        [void]$html.AppendLine('<ol>')
        foreach ($item in $orderedItems) {
            [void]$html.AppendLine("<li>$(Convert-InlineMarkup $item)</li>")
        }
        [void]$html.AppendLine('</ol>')
        $orderedItems.Clear()
    }
}

function Flush-Table {
    if ($tableLines.Count -gt 0) {
        [void]$html.AppendLine((Convert-Table $tableLines))
        $tableLines.Clear()
    }
}

function Flush-Code {
    if ($codeLines.Count -gt 0) {
        $text = [string]::Join([Environment]::NewLine, $codeLines)
        [void]$html.AppendLine("<pre>$(Escape-Html $text)</pre>")
        $codeLines.Clear()
    }
}

foreach ($line in $lines) {
    if ($line.Trim() -eq '```') {
        Flush-Paragraph
        Flush-UnorderedList
        Flush-OrderedList
        Flush-Table
        if ($inCodeBlock) {
            Flush-Code
            $inCodeBlock = $false
        }
        else {
            $inCodeBlock = $true
        }
        continue
    }

    if ($inCodeBlock) {
        $codeLines.Add($line)
        continue
    }

    if ([string]::IsNullOrWhiteSpace($line)) {
        Flush-Paragraph
        Flush-UnorderedList
        Flush-OrderedList
        Flush-Table
        continue
    }

    if ($line -match '^(###)\s+(.*)$') {
        Flush-Paragraph
        Flush-UnorderedList
        Flush-OrderedList
        Flush-Table
        [void]$html.AppendLine("<h3>$(Convert-InlineMarkup $matches[2].Trim())</h3>")
        continue
    }

    if ($line -match '^(##)\s+(.*)$') {
        Flush-Paragraph
        Flush-UnorderedList
        Flush-OrderedList
        Flush-Table
        [void]$html.AppendLine("<h2>$(Convert-InlineMarkup $matches[2].Trim())</h2>")
        continue
    }

    if ($line -match '^(#)\s+(.*)$') {
        Flush-Paragraph
        Flush-UnorderedList
        Flush-OrderedList
        Flush-Table
        [void]$html.AppendLine("<h1>$(Convert-InlineMarkup $matches[2].Trim())</h1>")
        continue
    }

    if ($line.TrimStart().StartsWith('|')) {
        Flush-Paragraph
        Flush-UnorderedList
        Flush-OrderedList
        $tableLines.Add($line)
        continue
    }

    if ($line -match '^\d+\.\s+(.*)$') {
        Flush-Paragraph
        Flush-UnorderedList
        Flush-Table
        $orderedItems.Add($matches[1].Trim())
        continue
    }

    if ($line -match '^[-*]\s+(.*)$') {
        Flush-Paragraph
        Flush-OrderedList
        Flush-Table
        $unorderedItems.Add($matches[1].Trim())
        continue
    }

    Flush-UnorderedList
    Flush-OrderedList
    Flush-Table
    $paragraphLines.Add($line.Trim())
}

Flush-Paragraph
Flush-UnorderedList
Flush-OrderedList
Flush-Table
Flush-Code

[void]$html.AppendLine('</body></html>')

$tempHtml = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("insight_proposal_{0}.html" -f [System.Guid]::NewGuid().ToString('N'))
[System.IO.File]::WriteAllText($tempHtml, $html.ToString(), [System.Text.UTF8Encoding]::new($false))

$word = $null
$document = $null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $document = $word.Documents.Open($tempHtml)
    $document.SaveAs2($OutputDocx, 16)
}
finally {
    if ($document -ne $null) {
        $document.Close()
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($document) | Out-Null
    }
    if ($word -ne $null) {
        $word.Quit()
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    }
    if (Test-Path -LiteralPath $tempHtml) {
        Remove-Item -LiteralPath $tempHtml -Force
    }
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

"Created: $OutputDocx"
