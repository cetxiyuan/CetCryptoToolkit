@echo off

echo [ %DATE% %TIME% ]: The remote script is executed >> script.log

:: 设置目标目录路径
:: set "scriptDir=%~dp0"
:: set "searchPath=%scriptDir%..\plugins"
:: set "fileToFind=CetLicensePlugin.dll"
:: set "cutoffDate=20/06/2025"  :: DD/MM/YYYY

:: echo searchPath=%searchPath%

:: 使用 forfiles 删除日期早于 30 天前的 CetLicensePlugin.dll 文件
:: forfiles /p "%searchPath%" /s /m "CetLicensePlugin.dll" /d -30 /c "cmd /c del /F @path"

exit
