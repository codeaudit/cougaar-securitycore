
SHELL = /bin/sh

#----------------------------------------------------------- SETUP
COUGAAR_INSTALL_PATH = ${HOME}/cougaar-8.4.1.1
COUGAARCLASSES = ${COUGAAR_INSTALL_PATH}/classes
CLASSPATH = ${COUGAARCLASSES}
#----------------------------------------------------------- MAKE ALL

#  $@      - Current target
#  $*      - Current target without extension
#  $<      - Current dependency

all: jar signhigh 

clean:
	@echo +++++++ Removing jarfiles
	rm -rf ${COUGAARCLASSES}/com ${COUGAARCLASSES}/org 
	@echo +++++++ Removing jarfiles
	rm -i ${COUGAARCLASSES}/bootstrap.jar
	rm -i ${COUGAARCLASSES}/securityservices.jar
# We use the -i option just in case you don't really want to delete everything

classes:
	@echo +++++++ Compiling the source code
	export COUGAAR_INSTALL_PATH; export COUGAARCLASSES; export CLASSPATH
	echo ${COUGAARCLASSES}
	./test/bin/myalpc src

jar:
# Build core.jar
#	@echo +++++++ Building core.jar
#	cd ${COUGAARCLASSES}; \
#	find org -path org/cougaar/core/security/bootstrap -prune -o -print > /tmp/${USER}-cougaar.make.1 ; \#	grep .class /tmp/${USER}-cougaar.make.1 > /tmp/${USER}-cougaar.make.2 ; \
#	jar cf core.jar `cat /tmp/${USER}-cougaar.make.2`
#	rm -f /tmp/${USER}-cougaar.make.1
#	rm -f /tmp/${USER}-cougaar.make.2
#	@echo +++++++ Done Building core.jar
#
# Build bootstrapper
	@echo +++++++ Building bootstrapper.jar
	cd ${COUGAARCLASSES}; \
	jar cf ${COUGAARCLASSES}/bootstrapper.jar org/cougaar/core/security/bootstrap
	@echo +++++++ Done Building bootstrapper.jar

# Build security services
	@echo +++++++ Building securityservices.jar
	cd ${COUGAARCLASSES}; \
	jar cf ${COUGAARCLASSES}/securityservices.jar com \
		org/cougaar/core/security/access \
		org/cougaar/core/security/crypto \
		org/cougaar/core/security/policy \
		org/cougaar/core/security/test \
		org/cougaar/core/security/util 
	@echo +++++++ Done Building securityservices.jar

signhigh: jar
	@echo +++++++ Signing bootstrapper.jar and core.jar
#	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
#		-storepass keystore ${COUGAARCLASSES}/core.jar privileged
	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
		-storepass keystore ${COUGAARCLASSES}/bootstrapper.jar bootstrapper
	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
		-storepass keystore ${COUGAARCLASSES}/securityservices.jar privileged
	@echo +++++++ Done signing bootstrapper.jar and core.jar

install:
	cp ${COUGAARCLASSES}/bootstrapper.jar ${COUGAAR_INSTALL_PATH}/lib
	cp ${COUGAARCLASSES}/securityservices.jar ${COUGAAR_INSTALL_PATH}/lib
