# PacMon - Dependency Check Runner for TeamCity

### BEGIN INIT PARAMS

[CmdletBinding()]
Param(
	# -target <relative path to scan>
	[Parameter(Mandatory=$TRUE)]
	[string]$target,
	
	# -java <full path to java>
	[Parameter(Mandatory=$FALSE)]
	[string]$java = "java",	
		
	# -dc <relative path to dependency check>
	[Parameter(Mandatory=$FALSE)]
	[string]$dc = "dc",
	
	# -opts <java command line parameters>
	[Parameter(Mandatory=$FALSE)]
	[string]$opts,
	
	# -etc <dependency check command line parameters>
	[Parameter(Mandatory=$FALSE)]
	[string]$etc,

	# -s <relative path to suppression file>
	[Parameter(Mandatory=$FALSE)]
	[string]$s = "suppress.xml",
	
	# -x <relative path to temporary xml file>
	[Parameter(Mandatory=$FALSE)]
	[string]$x = "output.xml",
	
	# -h <relative path to artifact html file>
	[Parameter(Mandatory=$FALSE)]
	[string]$h = "vulnerabilities.html"
)

### END INIT PARAMS

function Get-DependencyCheckArgs([string]$inputFilePath, [string]$outputFilePath, [string]$suppressionFilePath, [string]$additionalArgs){
	$format = Get-FileExtensionFromPath $outputFilePath
	[string]$dcArgs = '-a "VulnerabilityScan" -s "{0}" -o "{1}" -f "{2}"' -f $inputFilePath, $outputFilePath, $format
	
	if (Test-Path $suppressionFilePath) {
		$dcArgs = '{0} --suppression "{1}"' -f $dcArgs, $suppressionFilePath
	}
	
	if ($additionalArgs) {
		$dcArgs = '{0} {1}' -f $dcArgs, $additionalArgs
	}
	
	$dcArgs
}

function Run-DependencyCheck([string]$javaCmd, [string]$dcPath, [string]$cmdLineArgs){
	[string]$repoPath = '{0}\repo' -f $dcPath
	[string]$classPath = '"{0}"\etc;"{1}"\commons-cli\commons-cli\1.2\commons-cli-1.2.jar;"{1}"\org\owasp\dependency-check-core\1.2.9\dependency-check-core-1.2.9.jar;"{1}"\org\apache\commons\commons-compress\1.9\commons-compress-1.9.jar;"{1}"\commons-io\commons-io\2.4\commons-io-2.4.jar;"{1}"\commons-lang\commons-lang\2.6\commons-lang-2.6.jar;"{1}"\org\apache\lucene\lucene-core\4.7.2\lucene-core-4.7.2.jar;"{1}"\org\apache\lucene\lucene-analyzers-common\4.7.2\lucene-analyzers-common-4.7.2.jar;"{1}"\org\apache\lucene\lucene-queryparser\4.7.2\lucene-queryparser-4.7.2.jar;"{1}"\org\apache\lucene\lucene-queries\4.7.2\lucene-queries-4.7.2.jar;"{1}"\org\apache\lucene\lucene-sandbox\4.7.2\lucene-sandbox-4.7.2.jar;"{1}"\org\apache\velocity\velocity\1.7\velocity-1.7.jar;"{1}"\commons-collections\commons-collections\3.2.1\commons-collections-3.2.1.jar;"{1}"\com\h2database\h2\1.3.176\h2-1.3.176.jar;"{1}"\org\jsoup\jsoup\1.7.2\jsoup-1.7.2.jar;"{1}"\org\owasp\dependency-check-utils\1.2.9\dependency-check-utils-1.2.9.jar;"{1}"\org\owasp\dependency-check-cli\1.2.9\dependency-check-cli-1.2.9.jar' -f $dcPath, $repoPath						  
	$command = '{0} -classpath {1} -Dapp.name="dependency-check" -Dapp.repo="{2}" -Dapp.home="{3}" -Dbasedir="{3}" org.owasp.dependencycheck.App {4}' -f $javaCmd, $classPath, $repoPath, $dcPath, $cmdLineArgs
	Write-Output ("Executing: cmd.exe /C {0}" -f $command)
	& cmd.exe /C $command
}

function Validate-Dependencies([string]$xmlPath) {
	if (!(Test-Path $xmlPath)) {
		Write-Error ("XML output not found: {0}" -f $xmlPath)
		exit(1)
	}

	[xml]$xml = Get-Content $xmlPath	

	if (!$xml.analysis) {
		Write-Error "XML contains no analysis"
		Delete-File $xmlPath
		exit(1)
	}
	
	if (!$xml.analysis.dependencies.dependency) {
		Write-Error "Analysis contains no dependencies"
		Delete-File $xmlPath
		exit(0)
	}
	
	$xml.analysis.dependencies.dependency
}

function Parse-Dependencies($dependencies) {
	Foreach ($dependency IN $dependencies) {
		Parse-Dependency($dependency)
	}
}

function Parse-Dependency($dependency) {
	[string]$name = Clean-String($dependency.fileName)
	[string]$description = Clean-String($dependency.description)
	$vulnerabilities = $dependency.vulnerabilities.vulnerability
	$suppressedVulnerabilities = $dependency.vulnerabilities.suppressedVulnerability
	
	Start-Test $name
	
	if ($description) {
		Update-Test $name $description
	}
	
	if ($dependency.vulnerabilities) {
		Parse-Vulnerabilities $name $vulnerabilities $suppressedVulnerabilities
	}
	
	End-Test($name)
}

function Parse-Vulnerabilities([string]$name, $vulnerabilities, $suppressedVulnerabilities){
	$ignoreTest = (($vulnerabilities.Length -eq 0) -and ($suppressedVulnerabilities.Length -ne 0))
	
	Foreach ($vulnerability in $vulnerabilities) {
		Parse-Vulnerability $name $vulnerability
	}
	
	Foreach ($vulnerability in $suppressedVulnerabilities) {
		if ($ignoreTest) {
			Parse-Vulnerability $name $vulnerability "ignore"
		} else {
			Parse-Vulnerability $name $vulnerability "update"
		}
	}
}

function Parse-Vulnerability([string]$name, $vulnerability, [string]$action){
	[string]$vulnerabilityName = Clean-String($vulnerability.name)
	[string]$vulnerabilitySeverity = Clean-String($vulnerability.severity)
	[string]$message = "{0} ({1})" -f $vulnerabilityName, $vulnerabilitySeverity
	[string]$details = Clean-String($vulnerability.description)
	
	if ($action -eq "ignore") {
		Ignore-Test $name ('[SUPPRESSED] {0}' -f $message)
	} elseif ($action -eq "update") {
		Update-Test $name ('[SUPPRESSED] {0}' -f $message)
	} else {
		Fail-Test $name $message $details
	}
}

function Parse-SuppressedVulnerabilities([string]$name, $vulnerabilities){
	Foreach ($vulnerability in $vulnerabilities) {
		Parse-SuppressedVulnerability $name $vulnerability
	}
}

function Parse-SuppressedVulnerability([string]$name, $vulnerability){
	[string]$vulnerabilityName = Clean-String($vulnerability.name)
	[string]$vulnerabilitySeverity = Clean-String($vulnerability.severity)
	[string]$message = "[SUPPRESSED] {0} ({1})" -f $vulnerabilityName, $vulnerabilitySeverity
	
	Ignore-Test $name $message
}

function Has-Vulnerability($dependencies) {
	$vulnerabilityFound = $FALSE
	Foreach ($dependency IN $dependencies) {
		if ($dependency.vulnerabilities) {
			$vulnerabilityFound = $TRUE
		}
	}
	$vulnerabilityFound
}

### TeamCity Test Service Message functions

function Start-Test([string]$name){
	Write-Output ("##teamcity[testStarted name='{0}']" -f $name)
}

function Update-Test([string]$name, [string]$message){
	Write-Output ("##teamcity[testStdOut name='{0}' out='{1}']" -f $name, $message)
}

function Ignore-Test([string]$name, [string]$message){
	Write-Output ("##teamcity[testIgnored name='{0}' message='{1}']" -f $name, $message)
}

function Fail-Test([string]$name, [string]$message, [string]$details){
	Write-Output ("##teamcity[testFailed name='{0}' message='{1}' details='{2}']" -f $name, $message, $details)
}

function End-Test([string]$name){
	Write-Output ("##teamcity[testFinished name='{0}']" -f $name)
}

### General Purpose

function Clean-String([string]$string){
	$string = $string -replace "`t|`n|`r",""
	$string = $string -replace " ;|; ",";"
	$string = $string -replace "'",""
	$string
}

function Get-FileExtensionFromPath([string]$path){
	$parts = $path.Split('.')
	$ext = $parts[$parts.Length-1]
	$ext.ToUpper()
}

function Delete-File([string]$path) {
	Invoke-Expression ('DEL {0}' -f $path)
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

[string]$javaCmd = '{0} {1}' -f $java, $opts

[string]$scanArgs = Get-DependencyCheckArgs $inputPath $xmlPath $suppressPath $etc
Run-DependencyCheck $javaCmd $dcPath $scanArgs

$dependencies = Validate-Dependencies $xmlPath

Set-PSConsole

Parse-Dependencies $dependencies

Delete-File $xmlPath

if (Has-Vulnerability $dependencies) {
	Write-Output ("Vulnerability found -- generating report artifact: {0}" -f $htmlFilename)
	[string]$artifactArgs = Get-DependencyCheckArgs $inputPath $htmlPath $suppressPath $etc
	Run-DependencyCheck $javaCmd $dcPath $artifactArgs
}

exit(0)

### END SCRIPT