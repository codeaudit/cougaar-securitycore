
# Add $CIP/csmart/lib and ~/UL/automation to the load path

# NOTE: if ~/UL/automation exists, it will be used instead of the automation overlay
#       from update_cougaar

if  ! defined? CIP then
  CIP = ENV['CIP']
end

$:.unshift File.join(CIP, 'csmart', 'lib')
# $: << File.join('~', 'UL', 'automation')   # CVS
# $: << File.join(CIP, 'csmart', 'lib')      # cougaar lib

