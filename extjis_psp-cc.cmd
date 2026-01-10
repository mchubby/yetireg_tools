SET PYTHON=python

for %%f in (*.opcodescript) DO %PYTHON% %~dp0extjis_psp-cc.py %%f

pause
