
@echo off

SET CYGWIN_ROOT=C:\cygwin

SET PATH=.;%CYGWIN_ROOT%\bin;%PATH%


SET THIS_COMMAND=%0
SET CONFIG_FILE=%1
SET INTERACTIVE_PORT=%2
SET CONFIG_DIR=%3
SET NUM_PROCESSORS=%4
SET LOGIN_AT_HOST=%5
SET HOST_FILE=%6
SET REMOTE_PRODUCT_HOME=%7
SET REMOTE_RUN_MODE=%8
SET PRODUCT_HOME_BIN=%9
shift
SET SIMULATION_MODE=%9
shift
SET STAT_FILE_NAME=%9
shift
SET GUI_MODE=%9


bash -c "'%PRODUCT_HOME_BIN%/exata.remote.sh' '%CONFIG_FILE%' '%INTERACTIVE_PORT%' '%CONFIG_DIR%' '%NUM_PROCESSORS%' '%LOGIN_AT_HOST%' '%HOST_FILE%' '%REMOTE_PRODUCT_HOME%' '%REMOTE_RUN_MODE%' '%PRODUCT_HOME_BIN%' '%SIMULATION_MODE%' '%STAT_FILE_NAME%' '%GUI_MODE%' " 
