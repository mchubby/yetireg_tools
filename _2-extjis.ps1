#Get-ChildItem . -filter "*psp*.opcodescript" -name | % {
#Get-ChildItem . -filter "*x360*.opcodescript" -name | % {
Get-ChildItem . -filter "*.opcodescript" -name | % {
  Write-Host "python extjis_psp-cc.py $($_)" -foregroundcolor cyan
  c:\Python33\python extjis_psp-cc.py $_
  # cmd /c pause
}