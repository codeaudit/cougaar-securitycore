
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
	rm -rf ${COUGAARCLASSES}/com ${COUGAARCLASSES}/org 
	@echo +++++++ Removing jarfiles
	rm -f ${COUGAARCLASSES}/bootstrapper.jar
	rm -f ${COUGAARCLASSES}/securityservices.jar

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
	jar cf ${COUGAARCLASSES}/bootstrapper.jar org/cougaar/core/security/bootstrap/
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
		com/nai/security/certauthority \
		com/nai/security/access \
		com/nai/security/crypto \
		com/nai/security/monitoring \
		com/nai/security/policy \
		com/nai/security/test \
		com/nai/security/util \
		org/cougaar/core/security/policy 
	@echo +++++++ Done Building securityservices.jar

build-classes: installconf
	@echo +++++++ Compiling the source code
	export COUGAAR_INSTALL_PATH; export COUGAARCLASSES; export CLASSPATH
	echo ${COUGAARCLASSES}
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
	@echo +++++++ Done signing bootstrapper.jar and core.jar

install: installconf
	@echo +++++++ Installing jar files into ${COUGAAR_INSTALL_PATH}
	cp ${COUGAARCLASSES}/bootstrapper.jar ${COUGAAR_INSTALL_PATH}/lib
	cp ${COUGAARCLASSES}/securebootstrapper.jar ${COUGAAR_INSTALL_PATH}/lib
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
	cp -r test/configs/small-135 ${COUGAAR_INSTALL_PATH}/configs
	cp sys/*.jar ${COUGAAR_INSTALL_PATH}/sys
#	cp -r ./test/configs/demo ${COUGAAR_INSTALL_PATH}/configs/.
#	cp -r ./test/configs/ul-mini-config  ${COUGAAR_INSTALL_PATH}/configs/.

confnai:
	echo +++++++ Installing NAI configuration files
	cp test/configs/mysql/cougaar.rc ${COUGAAR_INSTALL_PATH}/configs/small-135
