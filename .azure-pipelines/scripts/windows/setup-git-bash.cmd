@echo off
setlocal enabledelayedexpansion
set "agentgit=%AGENT_HOMEDIRECTORY%\externals\git"
set "gitcopy=%AGENT_TEMPDIRECTORY%\git"
echo Copying !agentgit! to !gitcopy!...
xcopy /E /I /Q "!agentgit!" "!gitcopy!"
if not exist "!gitcopy!\usr\bin\sh.exe" (
	echo ##vso[task.logissue type=error]Could not find sh.exe at !gitcopy!\usr\bin\sh.exe
	exit /b 1
)
echo Copying !gitcopy!\usr\bin\sh.exe to !gitcopy!\usr\bin\bash.exe...
copy /Y "!gitcopy!\usr\bin\sh.exe" "!gitcopy!\usr\bin\bash.exe"
echo ##vso[task.prependpath]!gitcopy!\usr\bin
