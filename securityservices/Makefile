
SHELL = /bin/sh

#----------------------------------------------------------- SETUP
CLASSPATH = ${COUGAARCLASSES}
#----------------------------------------------------------- MAKE ALL

#  $@      - Current target
#  $*      - Current target without extension
#  $<      - Current dependency

all: build-classes jar signjar install

installclean: build-classes jar signjar install clean-data

clean:
	@echo +++++++ Removing jarfiles
	rm -rf ${COUGAARCLASSES}/com ${COUGAARCLASSES}/org ${COUGAARCLASSES}/edu
	@echo +++++++ Removing jarfiles
	rm -f ${COUGAARCLASSES}/bootstrapper.jar
	rm -f ${COUGAARCLASSES}/securityservices.jar
	rm -f ${COUGAARCLASSES}/CougaarCRLextensions.jar
	rm -f ${COUGAARCLASSES}/idmef.jar
    
clean-data:
	@echo +++++++ Removing configuration data

	rm -rf ${COUGAAR_INSTALL_PATH}/configs/small-135/Crypto-*
	rm -f  ${COUGAAR_INSTALL_PATH}/configs/small-135/keystore-*
	rm -f  ${COUGAAR_INSTALL_PATH}/configs/small-135/*.log

	rm -rf test/configs/ul-mini-config-openldap/Crypto-*
	rm -f  test/configs/ul-mini-config-openldap/*.log
	rm -f  test/configs/ul-mini-config-openldap/keystore-*

	rm -rf test/configs/certauthority/Crypto-*
	rm -f  test/configs/certauthority/keystoreTest

	rm -f  test/configs/demo/*.log
	rm -f  test/configs/demo/*.swp
	rm -rf ${COUGAAR_INSTALL_PATH}/P

jar: build-classes
# Build core.jar
#	@echo +++++++ Building core.jar
#	cd ${COUGAARCLASSES}; \
#	find org -path org/cougaar/core/security/bootstrap -prune -o -print > /tmp/${USER}-cougaar.make.1 ; \#	grep .class /tmp/${USER}-cougaar.make.1 > /tmp/${USER}-cougaar.make.2 ; \
#	jar cf core.jar `cat /tmp/${USER}-cougaar.make.2`
#	rm -f /tmp/${USER}-cougaar.make.1
#	rm -f /tmp/${USER}-cougaar.make.2
#	@echo +++++++ Done Building core.jar
#
# Build base bootstrapper
	@echo +++++++ Building bootstrapper.jar
	cd ${COUGAARCLASSES}; \
	jar cf ${COUGAARCLASSES}/bootstrapper.jar org/cougaar/core/security/bootstrap
	@echo +++++++ Done Building bootstrapper.jar
# Build secure bootstrapper 
	@echo +++++++ Building securebootstrapper.jar
	cd ${COUGAARCLASSES}; \
	jar cf ${COUGAARCLASSES}/securebootstrapper.jar com/nai/security/bootstrap
	@echo +++++++ Done Building securebootstrapper.jar

# Build security services
	@echo +++++++ Building securityservices.jar
	cd ${COUGAARCLASSES}; \
	jar cf ${COUGAARCLASSES}/securityservices.jar \
		`find org/cougaar/core/security com/nai/security -maxdepth 1 -mindepth 1 -type d -not -path '*/bootstrap'` 
	@echo +++++++ Done Building securityservices.jar
	@echo +++++++ Bulding jar for extensions
	  cd ${COUGAARCLASSES}; \
        jar cf ${COUGAARCLASSES}/CougaarCRLextensions.jar  com/nai/security/crlextension

# Build idmef library
	@echo +++++++ Building idmef.jar
	cd ${COUGAARCLASSES}; \
	jar cf ${COUGAARCLASSES}/idmef.jar edu/jhuapl/idmef/
	@echo +++++++ Done Building idmef.jar
	
build-classes: installconf
	@echo +++++++ Compiling the source code
	export COUGAAR_INSTALL_PATH; export COUGAARCLASSES; export CLASSPATH
	echo ${COUGAARCLASSES}
	@echo +++++++ JAVA HOME is at :
	echo ${JAVA_HOME}
	rm -rf ${COUGAARCLASSES}/*
	./test/bin/myalpc src

signjar: jar build-classes
	@echo +++++++ Signing bootstrapper.jar and core.jar
#	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
#		-storepass keystore ${COUGAARCLASSES}/core.jar privileged

	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
		-storepass keystore ${COUGAARCLASSES}/bootstrapper.jar bootstrapper

	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
		-storepass keystore ${COUGAARCLASSES}/securebootstrapper.jar bootstrapper

	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
		-storepass keystore ${COUGAARCLASSES}/securityservices.jar privileged

	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
		-storepass keystore ${COUGAARCLASSES}/CougaarCRLextensions.jar privileged
		
	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
		-storepass keystore ${COUGAARCLASSES}/idmef.jar privileged
	
	@echo +++++++ Done signing JAR files

install: installconf
	@echo +++++++ Installing jar files into ${COUGAAR_INSTALL_PATH}
	cp ${COUGAARCLASSES}/bootstrapper.jar ${COUGAAR_INSTALL_PATH}/lib
	cp ${COUGAARCLASSES}/securebootstrapper.jar ${COUGAAR_INSTALL_PATH}/lib
	cp ${COUGAARCLASSES}/securityservices.jar ${COUGAAR_INSTALL_PATH}/lib
	cp ${COUGAARCLASSES}/CougaarCRLextensions.jar ${COUGAAR_INSTALL_PATH}/lib
	cp ${COUGAARCLASSES}/idmef.jar ${COUGAAR_INSTALL_PATH}/lib
	
	@echo +++++++ Creating log directories
	rm -rf ${COUGAAR_INSTALL_PATH}/log
	mkdir ${COUGAAR_INSTALL_PATH}/log
	mkdir ${COUGAAR_INSTALL_PATH}/log/bootstrap
	mkdir ${COUGAAR_INSTALL_PATH}/log/core
	mkdir ${COUGAAR_INSTALL_PATH}/log/plugin

	rm -f ${COUGAAR_INSTALL_PATH}/sys/tomcat_33.jar 

	@echo Do not forget to run make confnai
	@echo DO NOT FORGET to modify the alpreg.ini file
	@echo +++++++ Done installing jar files and log directories

installconf:
	echo +++++++ Installing configuration files
	cp -r ./test/configs/common ${COUGAAR_INSTALL_PATH}/configs/
	cp -r test/configs/small-135 ${COUGAAR_INSTALL_PATH}/configs
	cp sys/*.jar ${COUGAAR_INSTALL_PATH}/sys
	cp lib/*.jar ${COUGAAR_INSTALL_PATH}/lib
#	cp -r ./test/configs/demo ${COUGAAR_INSTALL_PATH}/configs/.
#	cp -r ./test/configs/ul-mini-config  ${COUGAAR_INSTALL_PATH}/configs/.

	cp test/configs/tomcat4/server.xml ${COUGAAR_INSTALL_PATH}/webtomcat/data/conf
	cp test/configs/tomcat4/web.xml ${COUGAAR_INSTALL_PATH}/webtomcat/data/webapps/ROOT/WEB-INF/

confnai:
	echo +++++++ Installing NAI configuration files
	cp test/configs/mysql/cougaar.rc ${COUGAAR_INSTALL_PATH}/configs/small-135

doc:
	test/bin/generatedoc

