@echo off
setlocal
cd /d "%~dp0"

echo [1/3] Installing/Upgrading PyInstaller...
py -3 -m pip install --upgrade pyinstaller
if errorlevel 1 (
  echo [ERROR] Failed to install PyInstaller.
  exit /b 1
)

echo [2/3] Building EXE...
py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --name twitdelete-gui ^
  --add-data "twitdelete.py;." ^
  --add-data "twitdelete_official.py;." ^
  --add-data "auth.example.json;." ^
  twitdelete_gui.py
if errorlevel 1 (
  echo [ERROR] Build failed.
  exit /b 1
)

echo [3/3] Done.
echo EXE: "%~dp0dist\twitdelete-gui.exe"
exit /b 0
