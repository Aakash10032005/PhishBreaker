@echo off
REM Activate your virtualenv if needed, e.g.
REM call venv\Scripts\activate

REM Run training (optional) - uncomment if you want to retrain
REM python -m src.model_train

REM Start flask app
python -m app.main
pause
