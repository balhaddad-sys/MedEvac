@echo off
cd /d C:\Users\balha\Apps\MedEvac\MAK_Registry
echo Logging in to Firebase...
firebase login
echo.
echo Deploying database rules...
firebase deploy --only database --project unit-e-1d07b
echo.
echo Done! You can close this window.
pause
