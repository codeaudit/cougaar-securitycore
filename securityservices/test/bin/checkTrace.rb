#!/usr/bin/ruby

CIP=ENV['COUGAAR_INSTALL_PATH']
require '#{CIP}/operator/security/checkTraceLib'
processLogFiles()
