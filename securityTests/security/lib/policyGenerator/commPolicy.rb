if ! defined? CIP then
  CIP = ENV['CIP']
end

$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require 'security/scripts/setup_scripting'
require 'security/lib/common_security_rules'
require "mysql.o"

Cougaar::ExperimentMonitor.enable_stdout
Cougaar::ExperimentMonitor.enable_logging

include Cougaar



class CommPolicy

  def initialize(run)
    @dbUser                = "society_config"
    @dbHost                = "localhost"
    @dbPassword            = "s0c0nfig"
    @db                    = "cougaar104"
    @mysql                 = Mysql.connect(@dbHost, 
                                           @dbUser,
                                           @dbPassword, 
                                           @db)

    @allowed               = Hash.new()
    @indirectReportingHash = Hash.new()
    @enclaveHash           = Hash.new()
    @enclaveNodeHash       = Hash.new()
    @run                   = run
    @policyCounter         = 0
    @allowMultiple         = []
    @allowSingleSender     = Hash.new()
    @allowSingleReceiver   = Hash.new()
    @debug                 = false
  end


#
# Core methods
#
  def permit(senders, receivers)
    if senders.length == 1 then
      addAllowSingleSender(senders[0], receivers)
    elsif receivers.length == 1 then
      addAllowSingleReceiver(receivers[0], senders)
    else
      @policyCounter += 1
      @allowMultiple.push([senders, receivers])
    end
  end

  def permitSingle(sender, receiver)
    if @allowSingleReceiver[receiver] != nil &&
       @allowSingleReceiver[receiver].include?(sender) then
      return
    else 
      addAllowSingleSender(sender, [receiver])
    end
  end

  def addAllowSingleSender(sender, receivers)
    if @allowSingleSender[sender] == nil then
      @policyCounter += 1
      @allowSingleSender[sender] = [] 
    end
    arrayAdd @allowSingleSender[sender], receivers
  end

  def addAllowSingleReceiver(receiver, senders)
    if @allowSingleReceiver[receiver] == nil then
      @policyCounter += 1
      @allowSingleReceiver[receiver] = [] 
    end
    arrayAdd @allowSingleReceiver[receiver], senders
  end

  def arrayAdd(a1, a2)
    a2.each do |element|
      if !a1.include?(element) then
        a1.push(element)
      end
    end
    a1
  end

  def policyCount()
    @policyCounter
  end

  def viewPolicy()
    @allowMultiple.each do |p|
      puts "Members of [#{p[0].join(', ')}] can talk to members " +
            "of [#{p[1].join(', ')}]"
    end
    @allowSingleSender.each_key do |sender|
      puts "#{sender} can talk to members " +
            "of [#{@allowSingleSender[sender].join(', ')}]"
    end
    @allowSingleReceiver.each_key do |receiver|
      puts "Members of [#{@allowSingleReceiver[receiver].join(', ')}]" +
           " can talk to #{receiver}"
    end
    puts "#{@policyCounter} policies found"
  end

  def isMsgAllowed(sender, receiver)
    @allowMultiple.each do |p|
      if p[0].include?(sender) && p[1].include?(receiver) then
        return true
      end
    end
    if @allowSingleSender[sender] != nil && 
        @allowSingleSender[sender].include?(receiver) then
      return true
    end
    if @allowSingleReceiver[receiver] != nil &&
        @allowSingleReceiver[receiver].include?(sender) then
      return true
    end
    return false
  end

  def density()
    totalAgents = 0
    @run.society.each_agent do |agent|
      totalAgents += 1
    end
    debug "#{totalAgents} agents found"

    allowed = Hash.new()
    @allowMultiple.each do |p|
      p[0].each do |agent1|
        p[1].each do |agent2|
          addAllowed(allowed, agent1, agent2)
        end
      end
    end
    debug "done with multiple to multiple policies"

    @allowSingleSender.each_key do |sender|
      @allowSingleSender[sender].each do |receiver|
        addAllowed(allowed, sender, receiver)
      end
    end
    debug "done with single sender to multiple receivers policies"

    @allowSingleReceiver.each_key do |receiver|
      @allowSingleReceiver[receiver].each do |sender|
        addAllowed(allowed, sender, receiver)
      end
    end
    calcDensity(allowed, totalAgents)
  end

  def addAllowed(allowed, agent1, agent2)
    if allowed[agent1] == nil then
      allowed[agent1] = []
    end
    if (!allowed[agent1].include?(agent2)) then
      allowed[agent1].push(agent2)
    end
  end

  def calcDensity(allowed, totalAgents)
    count = 0
    allowed.each_key do |sender|
      count += allowed[sender].length
    end
    (count * 1.0) /(totalAgents * totalAgents)
  end

  def setDebug(flag)
    @debug=flag
  end

#
# Utility Routines
#

  def banner(text)
    debug("----------------------------------------------------")
    debug("                     #{text}")
    debug("----------------------------------------------------")
  end

  def getEnclaveAgents(enclave)
    if (@enclaveHash[enclave] == nil) then
      agents = []
      @run.society.each_enclave_agent(enclave, true) do |agent|
        agents.push(agent.name)
      end
      @enclaveHash[enclave] = agents
    else
      @enclaveHash[enclave]
    end
  end


  def getEnclaveNodes(enclave)
    if (@enclaveNodeHash[enclave] == nil) then
      nodes = []
      @run.society.each_enclave_node(enclave) do |node|
        nodes.push(node.name)
      end
      @enclaveNodeHash[enclave] = nodes
    else
      @enclaveNodeHash[enclave]
    end
  end

  def getNodes()
    nodes = []
    @run.society.each_node do |node|
      nodes.push(node.name)
    end
    nodes
  end

  def getAgents()
    agents = []
    @run.society.each_agent(true) do |agent|
      agents.push(agent.name)
    end
    agents
  end

  def getNodeFromAgent(agentname)
    @run.society.each_agent do |agent|
      if agent.name == agentname then 
        return agent.node.name
      end
    end
    raise "Agent has no node"
  end


#
# methods supporting allowing various communication
#

#==========================================================================
# Everybody should be able to talk to the name servers
#==========================================================================
  def allowNameService()
    banner("Allow Name Service")
    nameServers = getNameServers()
    agents = getAgents()
    permit(nameServers, agents)
    permit(agents, nameServers)
  end

  def getNameServers()
    nameServers = []
    @run.society.each_node do |node|
      node.each_facet(:role) do |facet|
        if facet[:role] == 'NameServer' then
          nameServers.push(node.name)
          break
        end
      end
    end
    debug "Found nameservers: #{nameServers.join(", ")}"
    nameServers
  end

#==========================================================================
# Members of a community can talk to the special community agents.
#==========================================================================

  def allowSpecialCommunity()
    banner("Allow special communities")
    debug "working on community policies"
    @run.society.communities.each do |community|
      debug "working on community #{community.name}"
      specialMembers = getSpecialCommunityAgentsRecursive(community)
      debug "special members = #{specialMembers.join(", ")}"
      permit(getNodes(), specialMembers)
      permit(specialMembers, getNodes())
#      getCommunityEnclaves(community).each do |enclave|
#        permit(getEnclaveNodes(enclave), specialMembers)
#        permit(specialMembers, getEnclaveNodes(enclave))
#      end
      members = getMembersRecursive(community)
      debug "members = #{members.join(", ")}"
      permit(members, specialMembers)
      permit(specialMembers, members)
    end    
  end

  def getCommunityEnclaves(community)
    enclaves = []
    debug("collecting enclaves")
    community.each do |entity|
      if entity.entity_type != "Agent" then
        next
      end
      agent = nil
      debug("have an entity (#{entity.name}) - looking for the agent name")
      @run.society.each_agent(true) do |anAgent|
        if anAgent.name == entity.name then
          agent = anAgent
          break
        end
      end
      
      if agent == nil then
        debug("not found")
        next
      end
      debug("found agent")
      if !enclaves.include?(agent.host.enclave) then
        enclaves.push(agent.host.enclave)
      end
      debug("bottom of entities loop")
    end
    debug("Finished entities loop for getCommunity Enclaves")
    if (enclaves.size > 1) then
      debug "Community #{community.name} spans enclaves"
    end
    debug("Finishing get enclave communities")
    enclaves
  end


  def getSpecialCommunityAgentsRecursive(community)
    debug "Entering get special community agents recusive for #{community.name}"
    agents = getSpecialCommunityAgentsNonRecursive(community)
    debug("Starting subcommunity loop")
#    community.each_subcommunity do |subcommunity|
    community.each do |entity|
      debug "subcommunity loop entity name = #{entity.name}"
      debug "subcommunity loop entiy type = #{entity.entity_type}"
      if entity.entity_type != 'Community' then
        next
      end
      subcommunity=nil
      @run.society.communities.each do |candidate|
        if candidate.name == entity.name then
          subcommunity = candidate
          break
        end
      end
      if subcommunity == nil then
        break
      end
      debug "Looking at subcommunity #{subcommunity.name}"
      getSpecialCommunityAgentsRecursive(subcommunity).each do |subagent|
        if ! agents.include?(subagent) then
          agents.push(subagent)
        end
      end
    end
    agents
  end

  def getSpecialCommunityAgentsNonRecursive(community)
    debug "Getting special community agents for #{community.name}"
    agents = []
    community.each_attribute do |id, value|
      debug "Examining #{id} with value #{value}"
      if id == 'CommunityManager' then
        agent = value
        debug( "agent #{agent} is special in " + 
               "community #{community.name} (manager)")
        agents.push(agent)
      end
    end
    community.each do |entity|
      debug("Examining entity #{entity.name}")
      if entity.entity_type != "Agent" then
        next
      end
      agent = entity.name
      special = false
      debug("Started role loop")
      entity.each_role do |role|
        debug "examining role #{role}"
        if role != 'Member' then
          special = true
          break
        end
      end
      debug("Ended role loop for #{entity.name}")
      if special && !agents.include?(agent) then
        agents.push(agent)
      end
      debug("At bottom of entity loop for community #{community.name}")
    end
    debug("Finished entity loop for community #{community.name}")
    agents
  end

  def getMembersRecursive(community)
    agents = getMembers(community)
    debug("GetMembers returned #{agents.join(', ')}")
    community.each do |entity|
      debug "subcommunity loop entity name = #{entity.name}"
      debug "subcommunity loop entiy type = #{entity.entity_type}"
      if entity.entity_type != 'Community' then
        next
      end
      subcommunity=nil
      @run.society.communities.each do |candidate|
        if candidate.name == entity.name then
          subcommunity = candidate
          break
        end
      end
      if subcommunity == nil then
        break
      end
      debug "Looking at subcommunity #{subcommunity.name}"
      getMembersRecursive(subcommunity).each do |agent|
        debug "Adding agent #{agent} for subcommunity #{subcommunity.name}"
        if !agents.include?(agent) then
          agents.push(agent)
        end
      end
    end
    agents
  end

  def getMembers(community)
    agents = []
    community.each do |entity|
      if entity.entity_type != "Agent" then
        next
      end
      agent = entity.name
      if !agents.include?(agent) then
        agents.push(agent)
      end
    end
    agents
  end

#==========================================================================
# YP servers can talk to each other (the rest is handled by the
#                                    community stuff?)
#==========================================================================

  def getYPServers()
    ypserverplugin = "org.cougaar.yp.YPServer"
    servers = []
    @run.society.each_agent do |agent|
      puts agent.name
      agent.each_component do |component|
        if (component.classname == ypserverplugin) then
          servers.push(agent.name)
        end        
      end
    end
    servers
  end

#==========================================================================
# Everybody should be able to talk to the core security managers
#==========================================================================

  def allowSecurityManagement()
    banner("Allow Security")
    @run.society.each_enclave() do |enclave|
      securityAgents = getSecurityAgents(enclave)
      permit(getEnclaveAgents(enclave), securityAgents)
      permit(securityAgents, getEnclaveAgents(enclave))
    end
  end


  def getSecurityAgents(enclave)
    debug "looking for security agents in enclave #{enclave}"
    securityFacets = [$facetRootCaManagerAgent, 
                      $facetRedundantRootCaManagerAgent,
                      $facetCaManagerAgent,
                      $facetRedundantCaManagerAgent,
                      $facetCrlManagerAgent,
                      $facetUserManagerAgent,
                      $facetRootMonitoringManagerAgent,
                      $facetMonitoringManagerAgent,
                      $facetPersistenceManagerAgent,
                      $facetRedundantPersistenceManagerAgent,
                      $facetPolicyManagerAgent,
                      $facetPolicyServletManagerAgent]

    agents=[]
    @run.society.each_enclave_agent(enclave) do |agent|
      agent.each_facet(:role) do |facet|
        debug "Found agent = #{agent.name} with facet = #{facet}"
        if facet[:role] != nil && securityFacets.include?(facet[:role]) then
          debug "Found security agent = #{agent.name}"
          agents.push(agent.name)
        end
      end
    end
    debug "Returning agents = #{agents.join(", ")}"
    agents
  end


#==========================================================================
# MnR managers can talk among themselves
#==========================================================================
  def allowInterMnR()
    banner("Allow Inter MnR")
    mnrs = getMnRManagers()
    permit(mnrs, mnrs)
  end

  def getMnRManagers()
    monitors = []
    monitoringFacets = [$facetRootMonitoringManagerAgent, 
                        $facetMonitoringManagerAgent]
    @run.society.each_agent do |agent|
      agent.each_facet do |facet|
        if monitoringFacets.include?(facet[:role]) then
          monitors.push(agent.name)
        end
      end
    end
    monitors
  end



#==========================================================================
# Subordinates are allowed to talk with their superiors
#==========================================================================

  def allowSuperiorSubordinate()
    banner("Allow Superior/Subordinate")
    @run.society.each_agent(true) do |agent|
      superior = agent.name
      debug "superior = #{superior}"
      subordinates = directlyReportingAll(superior)
      debug "subordinates = #{subordinates.join(',')}"
      permit([ superior ], subordinates)
      permit(subordinates, [ superior ])
    end
  end

  def allowSuperiorSubordinateLinear()
    banner("Allow Superior/Subordinate")
    levelSets = calculateLevelSets
    i = 0
    while (i < levelSets.size - 1) do
      permit(levelSets[i], levelSets[i+1])
      permit(levelSets[i+1], levelSets[i])
    end  
  end

  def calculateLevelSets(levelSets = [["OSD.GOV"]])
    last = levelSets.size - 1
    debug "last entry = #{last}"
    found = []
    i = 0
    while (i < last) do  # really! - I am not including the last one
      found += levelSets[i]
      i += 1
    end
    debug "found = [#{found.join(", ")}]"
    newLevelSet = []
    levelSets[last].each do |superior|
      debug "looking at superior #{superior}"
      if found.include?(superior) then
        debug "found loop at #{superior}"
      else 
        directlyReportingAll(superior).each do |subordinate|
          if ! newLevelSet.include? subordinate then
            newLevelSet.push(subordinate)
          end
        end
      end
    end
    debug "newLevelSet = [#{newLevelSet.join(", ")}]"
    debug "empty = #{newLevelSet.empty?}"
    if ! newLevelSet.empty? then
      levelSets += [ newLevelSet ]
      levelSets = calculateLevelSets(levelSets)
    end
    levelSets
  end

  def directlyReportingAll(superior)
    directlyReporting(superior) + 
      directlyReportingAdministrative(superior) +
      directlyReportingSupport(superior)
  end

  def directlyReporting(superior)
    subordinates = []
    @run.society.each_agent(true) do |agent|
      if agent.name == superior  then
        agent.each_facet(:subordinate_org_id) do |facet|
          facetval = facet[:subordinate_org_id]
          if facetval == nil || facetval == "" then
            next
          else
            if !subordinates.include?(facetval) then
              debug "#{facetval} reports to #{superior}"
              subordinates.push(facetval)
            end
          end
        end
      end
    end
    return subordinates
  end

  def directlyReportingAdministrative(superior)
    subordinates = []
    mysqlsubs = @mysql.query("select supporting_org_id " +
                             "from org_relation " +
                        "where supported_org_id = \'#{superior}\' " +
                        "and role = \'AdministrativeSubordinate\'")
    mysqlsubs.each do |row|
      if !subordinates.include?(row[0]) then
        debug "#{row[0]} reports to #{superior} (mysql)"
        subordinates.push(row[0])
      end
    end
    return subordinates
  end

  def directlyReportingSupport(superior)
    subordinates = []
    mysqlsubs = @mysql.query("select supporting_org_id " +
                             "from org_relation " +
                        "where supported_org_id = \'#{superior}\' " +
                        "and role = \'SupportSubordinate\'")
    mysqlsubs.each do |row|
      if !subordinates.include?(row[0]) then
        debug "#{row[0]} reports to #{superior} (mysql)"
        subordinates.push(row[0])
      end
    end
    return subordinates
  end

#
# Some relevant queries:
#
=begin

select x.supported_org_id from org_relation as x
  where x.role = 'AdministrativeSubordinate'
   and not exists (select * from org_relation as y
                      where y.supporting_org_id = x.supported_org_id);

select x.supported_org_id from org_relation as x
  where x.role = 'SupportSubordinate'
   and not exists (select * from org_relation as y
                      where y.supporting_org_id = x.supported_org_id);


select distinct role from org_relation;

=end




#==========================================================================
# Agents can talk to service providers
#==========================================================================

  def allowServiceProviders
    requires = getRequiresMap
    provides = getProvidesMap(requires.keys)
    requires.each_key do |providerType|
      debug "working on #{providerType}"
      clients = requires[providerType]
      servers = provides[providerType]
      if (servers == nil) then
        debug "#{clients} need service #{providerType} but nobody can give it"
      else 
        debug "the agents in #{clients} can talk to the agents in #{servers}"
        permit(clients, servers)
        permit(servers, clients)
      end
    end
  end

  def getRequiresMap()
    debug "entering getRequiresMap"
    sdclientplugin = 'org.cougaar.logistics.plugin.servicediscovery.ALDynamicSDClientPlugin'
    requiresMap = Hash.new()
    @run.society.each_agent do |agent|
      debug "examining agent #{agent.name}"
      agent.each_component do |component|
        if (component.classname == sdclientplugin) then
          debug "#{agent.name} uses the plugin"
          component.each_argument do |arg|
            providerType = stripProviderTypeSuffix(arg.value)

            debug "#{agent.name} needs \'#{providerType}\'"
            if (requiresMap[providerType] == nil) then
              requiresMap[providerType] = []
            end
            if (!requiresMap[providerType].include?(agent.name)) then
              requiresMap[providerType].push(agent.name)
            end
          end
        end
      end
    end
    requiresMap
  end

  def getProvidesMap(providerTypes)
    @agentInputs = "#{CIP}/servicediscovery/data/serviceprofiles/agent-input.txt"
    providesMap = Hash.new()
    # revision 1.1 uses the agent-input.txt file.
    providerTypes.each do |providerType|
      @run.society.each_agent do |agent|
        if providesMap[providerType] == nil then
          providesMap[providerType] = []
        end
        agent.each_facet do |facet|
          if facet[:role] != nil &&
             stripProviderTypeSuffix(facet[:role]) == providerType then
            providesMap[providerType].push(agent.name)
          end
        end
      end
    end
    providesMap
  end

  def stripProviderTypeSuffix(providerType)
    # strip off the trailing ":number" if it is there
    m = /^([^:]*)(:[0-9]*|)/.match(providerType)
    return m[1]
  end

#==========================================================================
# Agents can talk to themselves
#==========================================================================

  def allowTalkToSelf()
    banner("Allow Agents to mumble")
    @run.society.each_agent do |agent|
      permit(agent.name, agent.name)
    end
  end


#==========================================================================
# A node can talk to everybody in the enclave
#   we are avoiding using this.
#==========================================================================
  def allowNodeToEnclave()
    banner("Allow Node to enclave")
    @run.society.each_node do |node|
      @run.society.each_enclave_agent(node.host.enclave) do |agent|
        permitSingle(node.name, agent.name)
        permitSingle(agent.name, node.name)
      end
    end
  end



#==========================================================================
# Every node should be able to talk to everybody
#  Avoid
#==========================================================================
  def allowNodeToAll()
    bannner("Allow node to all")
    @run.society.each_node do |node|
      @run.society.each_agent(true) do |agent|
        permitSingle(node.name, agent.name)
        permitSingle(agent.name, node.name)
      end
    end
  end


#==========================================================================
#  END OF POLICIES
#==========================================================================

  def debug(info)
    puts(info) if @debug
  end

end
