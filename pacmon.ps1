# PacMon - Dependency Check Runner for TeamCity

### BEGIN INIT PARAMS

[CmdletBinding()]
Param(
	[Parameter(Mandatory=$TRUE)]
	[string]$target,
	
	[Parameter(Mandatory=$FALSE)]
	[string]$java="java",
	
	[Parameter(Mandatory=$FALSE)]
	[string]$dc="dc",
	
	[Parameter(Mandatory=$FALSE)]
	[string]$s = "suppress.xml",
	
	[Parameter(Mandatory=$FALSE)]
	[string]$x = 'output.xml',
	
	[Parameter(Mandatory=$FALSE)]
	[string]$h = 'vulnerabilities.html'
)

### END INIT PARAMS

function parseDependencies($dependencies) {
	Foreach ($dependency IN $dependencies) {
		parseDependency($dependency)
	}
}

function parseDependency($dependency) {
	[string]$name = cleanString($dependency.fileName)
	[string]$description = cleanString($dependency.description)
	$vulnerabilities = $dependency.vulnerabilities.vulnerability
	
	startTest $name
	
	if ($description) {
		updateTest $name $description
	}
	
	if ($dependency.vulnerabilities) {
		parseVulnerabilities $name $vulnerabilities
	}
	
	endTest($name)
}

function parseVulnerabilities([string]$name, $vulnerabilities){
	Foreach ($vulnerability in $vulnerabilities) {
		parseVulnerability $name $vulnerability
	}
}

function parseVulnerability([string]$name, $vulnerability){
	[string]$vulnerabilityName = cleanString($vulnerability.name)
	[string]$vulnerabilitySeverity = cleanString($vulnerability.severity)
	[string]$message = "{0} ({1})" -f $vulnerabilityName, $vulnerabilitySeverity
	[string]$details = cleanString($vulnerability.description)
	
	failTest $name $message $details
}

function hasVulnerability($dependencies) {
	$vulnerabilityFound = $FALSE
	Foreach ($dependency IN $dependencies) {
		if ($dependency.vulnerabilities) {
			$vulnerabilityFound = $TRUE
		}
	}
	$vulnerabilityFound
}

function startTest([string]$name){
	Write-Output ("##teamcity[testStarted name='{0}']" -f $name)
}

function updateTest([string]$name, [string]$text){
	Write-Output ("##teamcity[testStdOut name='{0}' out='{1}']" -f $name, $text)
}

function failTest([string]$name, [string]$message, [string]$details){
	Write-Output ("##teamcity[testFailed name='{0}' message='{1}' details='{2}']" -f $name, $message, $details)
}

function endTest([string]$name){
	Write-Output ("##teamcity[testFinished name='{0}']" -f $name)
}

function cleanString([string]$string){
	$string = $string -replace "`t|`n|`r",""
	$string = $string -replace " ;|; ",";"
	$string = $string -replace "'",""
	$string
}

function executeDependencyCheck([string]$javaCmd, [string]$dcPath, [string]$cmdLineArgs){
	[string]$repoPath = '{0}\repo' -f $dcPath
	
	# set classpath
	[string]$classPath = '"{0}"\etc;"{1}"\commons-cli\commons-cli\1.2\commons-cli-1.2.jar;"{1}"\org\owasp\dependency-check-core\1.2.9\dependency-check-core-1.2.9.jar;"{1}"\org\apache\commons\commons-compress\1.9\commons-compress-1.9.jar;"{1}"\commons-io\commons-io\2.4\commons-io-2.4.jar;"{1}"\commons-lang\commons-lang\2.6\commons-lang-2.6.jar;"{1}"\org\apache\lucene\lucene-core\4.7.2\lucene-core-4.7.2.jar;"{1}"\org\apache\lucene\lucene-analyzers-common\4.7.2\lucene-analyzers-common-4.7.2.jar;"{1}"\org\apache\lucene\lucene-queryparser\4.7.2\lucene-queryparser-4.7.2.jar;"{1}"\org\apache\lucene\lucene-queries\4.7.2\lucene-queries-4.7.2.jar;"{1}"\org\apache\lucene\lucene-sandbox\4.7.2\lucene-sandbox-4.7.2.jar;"{1}"\org\apache\velocity\velocity\1.7\velocity-1.7.jar;"{1}"\commons-collections\commons-collections\3.2.1\commons-collections-3.2.1.jar;"{1}"\com\h2database\h2\1.3.176\h2-1.3.176.jar;"{1}"\org\jsoup\jsoup\1.7.2\jsoup-1.7.2.jar;"{1}"\org\owasp\dependency-check-utils\1.2.9\dependency-check-utils-1.2.9.jar;"{1}"\org\owasp\dependency-check-cli\1.2.9\dependency-check-cli-1.2.9.jar' -f $dcPath, $repoPath
	
	$command = '{0} -classpath {1} -Dapp.name="dependency-check" -Dapp.repo="{2}" -Dapp.home="{3}" -Dbasedir="{3}" org.owasp.dependencycheck.App {4}' -f $javaCmd, $classPath, $repoPath, $dcPath, $cmdLineArgs
	Write-Output ("Executing cmd.exe /C {0}" -f $command)
	cmd.exe /C $command
}

#
# http://stackoverflow.com/questions/1183183/path-of-currently-executing-powershell-script
#
function Get-ScriptDirectory
{
	$Invocation = (Get-Variable MyInvocation -Scope 1).Value
	Split-Path $Invocation.MyCommand.Path
}

#
# https://confluence.jetbrains.com/display/TCD9/PowerShell
#
function Set-PSConsole {
	if (Test-Path env:TEAMCITY_VERSION) {
		try {
			$rawUI = (Get-Host).UI.RawUI
			$m = $rawUI.MaxPhysicalWindowSize.Width
			$rawUI.BufferSize = New-Object Management.Automation.Host.Size ([Math]::max($m, 500), $rawUI.BufferSize.Height)
			$rawUI.WindowSize = New-Object Management.Automation.Host.Size ($m, $rawUI.WindowSize.Height)
		} catch {}
	}
}

### BEGIN SCRIPT

[string]$suppressFilename = $s
[string]$xmlFilename = $x
[string]$htmlFilename = $h

[string]$basePath = Get-ScriptDirectory

[string]$dcPath = '{0}\{1}' -f $basePath, $dc
[string]$inputPath = '{0}\{1}' -f $basePath, $target
[string]$xmlPath = '{0}\{1}' -f $basePath, $xmlFilename
[string]$htmlPath = '{0}\{1}' -f $basePath, $htmlFilename
[string]$suppressPath = '{0}\{1}' -f $basePath, $suppressFilename

if (Test-Path $suppressPath) {
	[string]$scanArgs = '-a "VulnerabilityScan" -s "{0}" -o "{1}" -f "XML" --suppression "{2}"' -f $inputPath, $xmlPath, $suppressPath
	[string]$artifactArgs = '-a "VulnerabilityScan" -s "{0}" -o "{1}" -f "HTML" --suppression "{2}"' -f $inputPath, $htmlPath, $suppressPath
} else {
	[string]$scanArgs = '-a "VulnerabilityScan" -s "{0}" -o "{1}" -f "XML"' -f $inputPath, $xmlPath
	[string]$artifactArgs = '-a "VulnerabilityScan" -s "{0}" -o "{1}" -f "HTML"' -f $inputPath, $htmlPath
}

executeDependencyCheck $java $dcPath $scanArgs

if (Test-Path $xmlPath) {
	Write-Output ("Parsing XML output: {0}" -f $xmlPath)
} else {
	Write-Error ("XML output not found: {0}" -f $xmlPath)
	exit(1)
}

[xml]$xml = Get-Content $xmlPath	

if (!$xml.analysis) {
	Write-Error "XML contains no analysis"
	Invoke-Expression ('DEL {0}' -f $xmlPath)
	exit(1)
}

$dependencies = $xml.analysis.dependencies.dependency

if (!$dependencies) {
	Write-Error "Analysis contains no dependencies"
	Invoke-Expression ('DEL {0}' -f $xmlPath)
	exit(0)
}

Set-PSConsole

parseDependencies $dependencies

Invoke-Expression ('DEL {0}' -f $xmlPath)

if (hasVulnerability $dependencies) {
	Write-Output ("Vulnerability found -- generating report artifact: {0}" -f $htmlFilename)
	executeDependencyCheck $java $dcPath $artifactArgs
}

exit(0)

### END SCRIPT