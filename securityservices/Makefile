
SHELL = /bin/sh

#----------------------------------------------------------- SETUP
CLASSPATH = ${COUGAARCLASSES}
#----------------------------------------------------------- MAKE ALL

#  $@      - Current target
#  $*      - Current target without extension
#  $<      - Current dependency

all: jar signjar install

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
	jar cf ${COUGAARCLASSES}/bootstrapper.jar com/nai/security/bootstrap
	@echo +++++++ Done Building bootstrapper.jar

# Build security services
	@echo +++++++ Building securityservices.jar
	cd ${COUGAARCLASSES}; \
	jar cf ${COUGAARCLASSES}/securityservices.jar \
		com/nai/security/certauthority \
		com/nai/security/access \
		com/nai/security/crypto \
		com/nai/security/monitoring \
		com/nai/security/policy \
		com/nai/security/test \
		com/nai/security/util \
		org 
	@echo +++++++ Done Building securityservices.jar

signjar: jar
	@echo +++++++ Signing bootstrapper.jar and core.jar
#	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
#		-storepass keystore ${COUGAARCLASSES}/core.jar privileged
	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
		-storepass keystore ${COUGAARCLASSES}/bootstrapper.jar bootstrapper
	jarsigner -keystore ${COUGAAR_INSTALL_PATH}/configs/common/signingCA_keystore \
		-storepass keystore ${COUGAARCLASSES}/securityservices.jar privileged
	@echo +++++++ Done signing bootstrapper.jar and core.jar

install: installconf
	@echo +++++++ Installing jar files into ${COUGAAR_INSTALL_PATH}
	cp ${COUGAARCLASSES}/bootstrapper.jar ${COUGAAR_INSTALL_PATH}/lib
	cp ${COUGAARCLASSES}/securityservices.jar ${COUGAAR_INSTALL_PATH}/lib
	@echo +++++++ Creating log directories
	rm -rf ${COUGAAR_INSTALL_PATH}/log
	mkdir ${COUGAAR_INSTALL_PATH}/log
	mkdir ${COUGAAR_INSTALL_PATH}/log/bootstrap
	mkdir ${COUGAAR_INSTALL_PATH}/log/core
	mkdir ${COUGAAR_INSTALL_PATH}/log/plugin
	@echo +++++++ Done installing jar files and log directories

installconf:
	echo +++++++ Installing configuration files
	cp -r ./test/configs/common ${COUGAAR_INSTALL_PATH}/configs/
	cp sys/*.jar ${COUGAAR_INSTALL_PATH}/sys
#	cp -r ./test/configs/demo ${COUGAAR_INSTALL_PATH}/configs/.
#	cp -r ./test/configs/ul-mini-config  ${COUGAAR_INSTALL_PATH}/configs/.
