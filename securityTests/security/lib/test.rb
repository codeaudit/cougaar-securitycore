#!/usr/bin/env /bin/ruby

$LOAD_PATH.unshift "../../lib03"

require 'lib/web'
require 'lib/misc'
require 'lib/doIrb'

require 'lib/userDomainAux'


#---------------------------------------------------
# test userDomainAux.rb

case 'sb022'
when 'bmd'
   agentsUrl = 'http://bmd:9000/agents'
   userDomainUrl = 'http://localhost:9002/$UserAdmin/useradmin2'
when 'sb022'
   agentsUrl = 'http://sb044:8810/agents?suffix=.'
   userDomainUrl = 'http://sb041:8800/$RearUserAdminAgent/useradmin2'
end

response = getHtml(agentsUrl)
puts response.body
puts response.code


ud = UserDomain.new('RearUserDomainComm')
ud.url = userDomainUrl
puts ud.users.as_string
exit

puts 'deleting satan'
ud.deleteUser('RearUserDomainComm\satan')
puts ud.users.as_string
george = ud.user('george')
puts george

puts 'saving george as george2, w/o first role'
george.name = 'RearUserDomainComm\george2'
george.roles = george.roles[1..-1]
puts george
ud.recreateUser(george, false)

puts '-------'
george2 = ud.user('george2')
puts george2

puts '-------'
puts 'updating george2: removing first role, modifying a couple of fields'
george2.authreq = "BOTH"
george2.firstname = 'my name is george2'
george2.roles = george2.roles[1..-1]
ud.updateUser(george2)

puts '-------'
george2 = ud.user('george2')
puts george2
