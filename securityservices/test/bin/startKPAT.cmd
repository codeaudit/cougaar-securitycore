@echo off

set host=%1
set port=%2

set agentName=%3

echo %COUGAAR_INSTALL_PATH%


set CP=;\UL\cougaar\lib\aggagent.jar
set CP=%CP%;\UL\cougaar\lib\albbn.jar
set CP=%CP%;\UL\cougaar\lib\bootstrap.jar
set CP=%CP%;\UL\cougaar\lib\Commons_isat_plugins.jar
set CP=%CP%;\UL\cougaar\lib\Commons_isat_ticenvironment.jar
set CP=%CP%;\UL\cougaar\lib\community.jar
set CP=%CP%;\UL\cougaar\lib\contract.jar
set CP=%CP%;\UL\cougaar\lib\core.jar
set CP=%CP%;\UL\cougaar\lib\CougaarCRLextensions.jar
set CP=%CP%;\UL\cougaar\lib\csmart.jar
set CP=%CP%;\UL\cougaar\lib\datagrabber.jar
set CP=%CP%;\UL\cougaar\lib\fcsua.jar
set CP=%CP%;\UL\cougaar\lib\glm.jar
set CP=%CP%;\UL\cougaar\lib\idmef.jar
set CP=%CP%;\UL\cougaar\lib\javaiopatch.jar
set CP=%CP%;\UL\cougaar\lib\kaos.jar
set CP=%CP%;\UL\cougaar\lib\overlay.jar
set CP=%CP%;\UL\cougaar\lib\planning.jar
set CP=%CP%;\UL\cougaar\lib\qos.jar
set CP=%CP%;\UL\cougaar\lib\quo.jar
set CP=%CP%;\UL\cougaar\lib\safe.jar
set CP=%CP%;\UL\cougaar\lib\securebootstrapper.jar
set CP=%CP%;\UL\cougaar\lib\securityservices.jar
set CP=%CP%;\UL\cougaar\lib\server.jar
set CP=%CP%;\UL\cougaar\lib\servicediscovery.jar
set CP=%CP%;\UL\cougaar\lib\stoplight.jar
set CP=%CP%;\UL\cougaar\lib\toolkit.jar
set CP=%CP%;\UL\cougaar\lib\tutorial.jar
set CP=%CP%;\UL\cougaar\lib\uiframework.jar
set CP=%CP%;\UL\cougaar\lib\util.jar
set CP=%CP%;\UL\cougaar\lib\vishnu.jar
set CP=%CP%;\UL\cougaar\lib\webserver.jar
set CP=%CP%;\UL\cougaar\lib\webtomcat.jar
set CP=%CP%;\UL\cougaar\lib\yp.jar

set CP=%CP%;\UL\cougaar\sys\antlr.jar
set CP=%CP%;\UL\cougaar\sys\bcprov-jdk14-118.jar
set CP=%CP%;\UL\cougaar\sys\chart.jar
set CP=%CP%;\UL\cougaar\sys\concurrent.jar
set CP=%CP%;\UL\cougaar\sys\dl.jar
set CP=%CP%;\UL\cougaar\sys\fesi-111.jar
set CP=%CP%;\UL\cougaar\sys\grappa1_2.jar
set CP=%CP%;\UL\cougaar\sys\hsqldb.jar
set CP=%CP%;\UL\cougaar\sys\httpunit.jar
set CP=%CP%;\UL\cougaar\sys\ibmpkcs.jar
set CP=%CP%;\UL\cougaar\sys\icu4j.jar
set CP=%CP%;\UL\cougaar\sys\iw.jar
set CP=%CP%;\UL\cougaar\sys\jakarta-oro-2.0.5.jar
set CP=%CP%;\UL\cougaar\sys\jas.jar
set CP=%CP%;\UL\cougaar\sys\jasper-runtime.jar
set CP=%CP%;\UL\cougaar\sys\jcchart.jar
set CP=%CP%;\UL\cougaar\sys\jdom.jar
set CP=%CP%;\UL\cougaar\sys\jena.jar
set CP=%CP%;\UL\cougaar\sys\jpcsc.jar
set CP=%CP%;\UL\cougaar\sys\jpython.jar
set CP=%CP%;\UL\cougaar\sys\jtp.jar
set CP=%CP%;\UL\cougaar\sys\juddi.jar
set CP=%CP%;\UL\cougaar\sys\junit.jar
set CP=%CP%;\UL\cougaar\sys\log4j.jar
set CP=%CP%;\UL\cougaar\sys\mail.jar
set CP=%CP%;\UL\cougaar\sys\mm-mysql-2.jar
set CP=%CP%;\UL\cougaar\sys\ontologyRepInit.jar
set CP=%CP%;\UL\cougaar\sys\openmap.jar
set CP=%CP%;\UL\cougaar\sys\polCert.jar
set CP=%CP%;\UL\cougaar\sys\quoSumo.jar
set CP=%CP%;\UL\cougaar\sys\servlet.jar
set CP=%CP%;\UL\cougaar\sys\silk.jar
set CP=%CP%;\UL\cougaar\sys\tomcat_40.jar
set CP=%CP%;\UL\cougaar\sys\tools.jar
set CP=%CP%;\UL\cougaar\sys\uddi4j.jar
set CP=%CP%;\UL\cougaar\sys\vgj.jar
set CP=%CP%;\UL\cougaar\sys\vishnuServer.jar
set CP=%CP%;\UL\cougaar\sys\xerces.jar

set MYPROPERTIES=-Dlog4j.configuration=%COUGAAR_INSTALL_PATH%\configs\common\loggingConfig.conf
set MYPROPERTIES=%MYPROPERTIES% -Dorg.cougaar.system.path=%COUGAAR_INSTALL_PATH%\sys -Dorg.cougaar.install.path=%COUGAAR_INSTALL_PATH% -Dorg.cougaar.core.servlet.enable=true -Dorg.cougaar.lib.web.scanRange=100 -Dorg.cougaar.lib.web.http.port=%port% -Dorg.cougaar.lib.web.https.port=-1 -Dorg.cougaar.lib.web.https.clientAuth=true

set MYMEMORY=
set MYCLASSES=kaos.kpat.applet.KPATAppletMain
set MYARGUMENTS=http://%host%:%port%/$%agentName%/policyAdmin true

java -classpath %CP% %MYPROPERTIES% %MYMEMORY% %MYCLASSES% %MYARGUMENTS%

