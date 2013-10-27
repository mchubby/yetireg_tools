#e.g. psp-sn.bin, x360-sn.bin

Get-ChildItem . -filter "*-sn.bin" -name | % {
  Write-Host "python extract_snbin.py $($_)" -foregroundcolor cyan
  c:\Python33\python extract_snbin.py $_
  # cmd /c pause
}