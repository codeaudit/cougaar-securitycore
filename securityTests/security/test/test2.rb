
CIP = ENV['CIP']
RULES = File.join(CIP, 'csmart','config','rules')
RULES1 = File.join(CIP, 'csmart','config','rules')

#$stdout.sync = true
#putc "."
#sleep 2
#putc "."
#exit

$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib')
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist')
$:.unshift File.join(CIP, 'csmart', 'config', 'lib')

# Uncomment the following two lines if working in the CSI testbed
$:.unshift File.join(CIP, 'csmart', 'lib')
require 'security/lib/scripting'

require 'security/lib/securityMops'

class A
  def name
    return "foo"
  end
end

$VerboseDebugging=true
mopC = SecurityMop21.new(A.new)
mop = mopC.calculate
puts "MOP: " + mop.to_s
