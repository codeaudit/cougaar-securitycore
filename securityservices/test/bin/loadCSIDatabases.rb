#!/usr/bin/ruby

CIP=ENV['CIP']

$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require "security/lib/scripting"
require "security/lib/security"
require "security/lib/stresses/reportChainReady"

Cougaar.new_experiment().run(1) do
  puts "Loading mySociety.xml - this might take a while"
  do_action "LoadSocietyFromXML", "mySociety.xml"

  `rm /tmp/relations.sql`

  do_action "GenericAction" do |run|
    puts "mySociety.xml loaded (finally!)"
    `date`
    File.open("/tmp/relations.sql", "w") do |sqlFile|
      File.open("/tmp/ruby", "w") do |rubyFile|
        sqlFile.puts "use cougaar104"
        sqlFile.puts "create table if not exists csi_subordinates"
        sqlFile.puts "     (subordinate varchar(150), superior varchar(150));"
        sqlFile.puts "delete from csi_subordinates;"
        sqlFile.puts "create table if not exists csi_enclave"
        sqlFile.puts "     (agent varchar(150), enclave varchar(150));"
        sqlFile.puts "delete from csi_enclave;"

        society.each_agent(true) do |agent|
          facetval = agent.get_facet(:superior_org_id)
          if facetval != nil
            sqlFile.puts "insert into csi_subordinates (subordinate, superior) "
            sqlFile.puts "   values ('#{agent.name}', '#{facetval}');"
            rubyFile.puts "rcr.addExpectedRelation(\"#{agent.name}\", \"#{facetval}\")"
          end  
        end
        society.each_node do |node|
          enclave = node.host.get_facet(:enclave)
          if enclave != nil
            sqlFile.puts "insert into csi_enclave (agent, enclave) "
            sqlFile.puts "   values ('#{node.name}', '#{enclave}');"
            node.each_agent do |agent|
              sqlFile.puts "insert into csi_enclave (agent, enclave) "
              sqlFile.puts "   values ('#{agent.name}', '#{enclave}');"
            end
          end  
        end
      end
      `cat /tmp/relations.sql | mysql -h cougaar-db -u society_config -ps0c0nfig`
    end
  end
end


