
require 'security/lib/common_security_rules'

class CertRevocation
   attr_accessor :management
   attr_accessor :canodes
   attr_accessor :normal_nodes

   def initialize
     @management = {}
     @canodes = {}
     @normal_nodes = {}

     distinguishNodes
   end

   def getManagement
     return management
   end

   def distinguishNodes
      run.society.each_node do |node|
#        puts "working on #{node.name}"
        untouchable = false
        node.each_facet do |facet|
          if facet['role'] == $facetManagement
            # do not revoke management agents
            management[node.name] = node
            untouchable = true
          end
          if facet['role'] =~ /CertificateAuthority/
            canodes[node.name] = node
            untouchable = true
            break
          end
        end

        if !untouchable
          normal_nodes[node.name] = node
        end
      end


   end

   def selectNode
      index = rand(normal_nodes.size)
      return normal_nodes.values[index]
   end

   def selectAgent
      node = selectNode
      return selectAgentFromNode(node)
   end

   def selectAgentFromNode(node)
     index = rand(node.agents.size)
     a = node.agents[index]
     if a != nil
        return a.name
     end
     return nil
   end

   def revokeNode(node) 
     saveUnitTestResult("Revocation", "revoking node #{node.name}")
     agent = node.agents[0]
     caDomains = run.society.agents[agent.name].caDomains
     
     return revoke(node.name, caDomains)
   end

            def revokeAgent(agent)
              saveUnitTestResult("Revocation", "revoking agent #{agent}")
              caDomains = run.society.agents[agent].caDomains
              return revoke(agent, caDomains)
            end

            def revoke(agent, caDomains)
     CaDomains.instance.getActualEntities
              caManager = caDomains[0].signer
              cadn = caDomains[0].cadn
              puts "cadn #{cadn}"

              url = "#{caManager.uri}/CA/RevokeCertificateServlet"
              # role = getParameter(ca.node, /security.role/, nil)
              
#              dn_names = getDistinguishNames(caDomains)
#              dnname = dn_names[agent]
###              dnname = caDomains[0].distinguishedNames[agent]
puts agent
#doIrb
              obj = run.society.agents[agent]
              if obj == nil
                obj = run.society.nodes[agent]
                if obj != nil
                  obj = obj.agent
                end
              end
              dnname = obj.distinguishedName
              puts "dnname #{dnname}"
              if dnname == nil
puts "WARNING:  no dnname, returning"
exit
                return false
              end

              params = ["cadnname=#{CGI.escape(cadn)}", "distinguishedName=#{dnname}"]
          ##    set_auth('george', 'george')
puts "params: #{params}"
              response = postHtml(url, params)

puts "response.code #{response.code}, body #{response.body}"
#              puts "revocation response #{response.body.to_s}"
              if response.body.to_s =~ /Success/
                puts "Successfully revoked #{agent}"
                return true
              else
                puts "Revoke #{agent} failed"
              end
              return false
            end

# for expiration
  def installExpirationPlugin(node)  
# node to ignore expired cert
    node.add_component do |c|
#      c.classname = 'org.cougaar.core.servlet.SimpleServletComponent'
      c.classname = 'org.cougaar.core.security.certauthority.CaServletComponent'
      c.add_argument("org.cougaar.core.security.crypto.servlet.MakeCertificateServlet")
      c.add_argument("/MakeCertificateServlet")
    end

  end

  def setNodeExpiration(node, timeString)
puts "expiring #{node.name}"

    agent = node.agents[0]
    setCAExpirationAttrib(agent, timeString)

    port = getParameter(node, /http.port/, nil)
    url = "http://#{node.host.name}:#{port}/$#{node.name}/MakeCertificateServlet"
    params = ["identifier=#{node.name}"]
    response = postHtml(url, params)
    raise "Failed to get new certificate. Error #{response.body.to_s}" unless response.body.to_s =~ /Success/
  end

  def setAgentExpiration(agent, timeString)
    agent = run.society.agents[agent] if agent.kind_of?(String)
    setCAExpirationAttrib(agent.name, timeString)
    removeAgentIdentities(agent)
  end

  def removeAgentIdentities(agent)
    agent = run.society.agents[agent] if agent.kind_of?(String)
puts "remove identities of #{agent.name}"
    node = agent.node

    port = getParameter(node, /http.port/, nil)
    url = "http://#{node.host.name}:#{port}/$#{node.name}/MakeCertificateServlet"
    params = ["identifier=#{agent.name}"]
    response = postHtml(url, params)
    unless response.body.to_s =~ /Success/
      puts response.body
    end
    raise "Failed to get new certificate. Error #{response.body.to_s}" unless response.body.to_s =~ /Success/
    
  end

  def setCAExpirationAttrib(agent, timeString)
    agent = run.society.agents[agent] if agent.kind_of?(String)
    caDomains = run.society.agents[agent.name].caDomains
    caManager = caDomains[0].signer
    cadn = caDomains[0].cadn
puts "cadn #{cadn}"

    url = "#{caManager.uri}/CA/CAInfoServlet"
    params = ["howLong=#{timeString}"]
    response = postHtml(url, params)
    raise "Failed to set CA expiration: #{response.body.to_s}" unless response.body.to_s =~ /Changed/
  end

      # get parameter from node given param name
      def getParameter(node, paramName, default)
        node.each_parameter do |p|
          (name, value) = p.to_s.split('=')
          return value if name =~ paramName
        end

        puts "No parameter found for #{paramName} on #{node.name}"
        return default
      end
end

