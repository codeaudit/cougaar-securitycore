
SHELL = /bin/sh

#----------------------------------------------------------- SETUP


#----------------------------------------------------------- MAKE ALL

#  $@      - Current target
#  $*      - Current target without extension
#  $<      - Current dependency

all: jar signhigh copy

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
#	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/.bootstrap_keystore \
#		-storepass keystore ${COUGAARCLASSES}/core.jar privileged
	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/.bootstrap_keystore \
		-storepass keystore ${COUGAARCLASSES}/bootstrapper.jar bootstrapper
	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/.bootstrap_keystore \
		-storepass keystore ${COUGAARCLASSES}/securityservices.jar privileged
	@echo +++++++ Done signing bootstrapper.jar and core.jar

copy:
#	cp ${COUGAARCLASSES}/core.jar ${COUGAAR_INSTALL_PATH}/lib
	cp ${COUGAARCLASSES}/bootstrapper.jar ${COUGAAR_INSTALL_PATH}/lib
	cp ${COUGAARCLASSES}/securityservices.jar ${COUGAAR_INSTALL_PATH}/lib
