SET PYTHON=C:\Python33\python

for %%f in (*.opcodescript) DO %PYTHON% %~dp0extjis_psp-cc.py %%f

pause
