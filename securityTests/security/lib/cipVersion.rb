#!/usr/bin/ruby
####################################################

if $cip_version == nil
  # Get the version of COUGAAR
  `cd /tmp ; jar xvf #{CIP}/lib/core.jar Manifest/core.version`
  File.open("/tmp/Manifest/core.version") do |fd|
    fd.each_line do |line|
      # REPOSITORY_TAG=B11_2
      if line =~ /REPOSITORY_TAG=(.*)/
         $cip_version = line.sub(/REPOSITORY_TAG=(.*)/, '\1').chomp
         $cip_version_major = $cip_version.sub(/B([^_]*)_(.*)/, '\1')
         $cip_version_minor = $cip_version.sub(/B([^_]*)_(.*)/, '\2')

         $cip_version = line.sub(/REPOSITORY_TAG=(.*)/, '\1').chomp
         $cip_version_major = $cip_version.sub(/B([^_]*)_([^_]*).*/, '\1')
         $cip_version_minor = $cip_version.sub(/B([^_]*)_([^_]*).*/, '\2')

         if $cip_version =~ /HEAD/ || $cip_version_major.to_i > 11 || ($cip_version_major.to_i == 11 && $cip_version_minor.to_i >= 4)
            $cip_version_b11_4_or_above = true
         else
            $cip_version_b11_4_or_above = false
         end
      end
    end
  end
  `rm /tmp/Manifest/core.version`
end
