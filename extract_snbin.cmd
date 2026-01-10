SET PYTHON=python

for %%f in (*-sn.bin) DO %PYTHON% %~dp0extract_snbin.py %%f

pause
