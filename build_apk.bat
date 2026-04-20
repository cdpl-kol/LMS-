@echo off
set JAVA_HOME=C:\Program Files\Android\Android Studio\jbr
set PATH=%JAVA_HOME%\bin;%PATH%
set ANDROID_HOME=C:\Users\Aadil Shaikh\AppData\Local\Android\Sdk
cd /d C:\Users\Aadil Shaikh\Downloads\LMS\android
gradlew.bat assembleDebug --no-daemon

