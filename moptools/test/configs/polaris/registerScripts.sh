#!/bin/sh

# Replace u180 in p-config.rb script
#
if [ ! -f $CIP/csmart/acme_scripting/bin/p-config.rb.ori ]; then
  mv $CIP/csmart/acme_scripting/bin/p-config.rb $CIP/csmart/acme_scripting/bin/p-config.rb.ori
fi
sed -e s/\"u180/\"polaris.ultralog.net/ $CIP/csmart/acme_scripting/bin/p-config.rb.ori > \
   $CIP/csmart/acme_scripting/bin/p-config.rb


# Register scripts


