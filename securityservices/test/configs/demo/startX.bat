@echo off
SET DISPLAY=127.0.0.1:0.0
SET PATH=.;%PATH%;\cygwin\bin;\cygwin\usr\X11R6\bin

rem cleanup after last run
attrib -s \cygwin\tmp\.X11-unix\X0
del \cygwin\tmp\.X11-unix\X0
rmdir \cygwin\tmp\.X11-unix


start XWin -screen 0 1024x768x32 -engine 4


start /B rxvt -geometry 50x10 -name dogwood -e bash

rem start /B mxterm -sl 1000 -sb -rightbar -ms red -fg yellow -bg black -e /usr/bin/bash
start /B twm

REM set stty=intr ^c susp ^z start ^q stop ^s quit ^\\ erase ^?
@echo on
