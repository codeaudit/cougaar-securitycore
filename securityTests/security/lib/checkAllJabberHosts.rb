#!/usr/bin/env ruby

require 'jabber4r/jabber4r'
include Jabber

def checkAllJabberHosts(run)

   acmehost = ''
   run.society.each_host do |host|
      acmehost = host.name if host.get_facet('service')=='jabber'
   end
   if acmehost==''
      puts "**************** ERROR **************"
      puts "no jabber service found in the society" if acmehost==''
      puts "*************************************"
   end
   puts "acme jabber service is #{acmehost}"

   allHosts = []
   activeHosts = []
   chattingHosts = []
   societyHosts = []
   run.society.each_host {|host| societyHosts << "#{host.name}@#{acmehost}"}
   puts "all society hosts: [#{societyHosts.sort.join(', ')}]"
   puts
   session = Session.bind_digest("acme_console@#{acmehost}/script", "c0ns0le")
   sleep 5
   begin
      session.roster.each_item do |item|
         hostname = item.jid.to_s
         if societyHosts.member? hostname
            item.each_resource do |resource|
               allHosts << hostname
               if resource.show == "chat" # online and available
                  chattingHosts << hostname
                  msg = session.new_chat_message(item.jid)
                  msg.body = "command[rexec]pwd" # reboot in 2 minutes
                  msg.send(true, 1) do |replymsg|
                     if replymsg.to_s.scan('/usr/local/acme')
                        activeHosts << hostname
                     else
                        puts "pwd is not /usr/local/acme on host #{hostname}: #{replymsg.to_s}"
                     end
                  end
               end
            end
         end
      end
   ensure
      puts "society hosts logged on to jabber server: [#{activeHosts.sort.join(', ')}]"
      puts
      nonresponsiveHosts = allHosts - activeHosts
      puts "*** nonresponsive hosts: [#{nonresponsiveHosts.sort.join(', ')}]" if nonresponsiveHosts != []
      puts if nonresponsiveHosts != []
      nonChatters = allHosts - chattingHosts
      puts "*** hosts without 'chat' capability: [#{nonChatters.sort.join(', ')}]" if nonChatters != []
      puts if nonChatters != []
      inactiveHosts = societyHosts - allHosts
      puts "*** hosts not logged on to jabber: [#{inactiveHosts.sort.join(', ')}]" if inactiveHosts != []
      puts "all hosts are active and accounted for" if nonresponsiveHosts==[] and inactiveHosts==[]
      session.release
   end
end

module Cougaar
 module Actions
  class CheckAllJabberHosts < Cougaar::Action
    def perform
      checkAllJabberHosts(@run)
    end
  end
 end
end

#checkAllJabberHosts

