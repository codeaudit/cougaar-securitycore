#!/usr/bin/ruby

require "security/lib/policy_util.rb"
require "security/lib/policyGenerator/commPolicy.rb"
require 'security/lib/web'

def buildInitialUrPolicies(run,
                           dbUser     = "society_config",
                           dbHost     = "cougaar-db",
                           dbPassword = "s0c0nfig",
                           db         = "cougaar104")
  p = CommPolicies.new(run, dbUser, dbHost, dbPassword, db)
  p.commonDecls()
  p.communityDecls()
  p.allowNameService()
  p.allowSpecialCommunity()
  p.allowRestartCommunityNodesTalk()
  p.allowHealthMonitoring()
  p.allowSecurityManagement()
  p.allowSuperiorSubordinate()
  p.allowInterMnR()
  p.allowServiceProviders()
  p.allowTalkToSelf()
  p
end


module Cougaar
  module Actions
    class GeneratePoliciesAction < Cougaar::Action
      def initialize(run)
	super(run)
        @run = run
        @staging = File.join(CIP, "workspace", "URPolicies")
        @debug=false
        @skipEnclaves = []
      end
    
      def policyFileName
        raise "Abstract class"
      end

      def isDelta
        raise "AbstractClass"
      end

      def fromConfig
        false
      end

      def skipEnclaves(enclaves)
        @skipEnclaves = enclavs
      end

      def perform
        raise "Abstract Class"
      end

      def compilePolicies
        file = policyFileName()+"-AllEnclaves"
        output = policyUtil("--maxReasoningDepth 150 build #{file}", nil,@staging)
        debug"#{output}"
      end

      def commitPolicies(precompiled, wait)
        pws=[]
        @run.society.each_enclave do |enclave|
          if @skipEnclaves.include?(enclave) then
            debug("skipping enclave #{enclave}")
            next
          end
          if wait then
            pws.push(PolicyWaiter.new(@run, getEnclaveNode(enclave)))
          end
          Thread.fork do
            begin 
              file = "#{policyFileName()}-#{enclave}"
              host, port, manager = getPolicyManager(enclave)
              debug "for enclave found #{host}, #{port}, #{manager}"
              debug "waiting for user manager"
              debug "fromConfig  = #{fromConfig()}"
              waitForUserManager(manager)
              debug "user manager ready"
              mutex = getPolicyLock(enclave)
              mutex.synchronize do
                debug "committing policy"
                result = commitPolicy(host, port, manager, 
                                      (fromConfig() ? "--useConfig " : "") +
                                      (isDelta() ? "addpolicies" : "commit") +
                                      (precompiled ? " " : " --dm "),
                                      file,@staging)
                debug("Result for enclave #{enclave} = #{result}")
                @run.info_message "policy committed for enclave #{enclave}\n"
              end
            rescue => ex
              @run.info_message("Exception in policy code - #{ex} #{ex.backtrace.join("\n")}")
            end
          end
        end
        if wait then
          debug "starting wait"
          pws.each do |pw|
            debug "waiting  for node #{pw}"
            if !pw.wait(3000) then
              raise "Policy did not propagate"
            end
            debug "#{pw} wait completed."
          end
        end
      end

      def setDebug(flag)
        @debug = flag
      end
        
      def debug(s)
        if @debug then
          puts("#{s}\n")
        end
      end

      def getEnclaveNode(enclave)
        @run.society.each_enclave_node(enclave) do |node|
          return node.name
        end
      end
    end

 
    class BuildURPolicies < Cougaar::Actions::GeneratePoliciesAction
      def initialize(run,
                     dbUser     = "society_config",
                     dbHost     = "cougaar-db",
                     dbPassword = "s0c0nfig",
                     db         = "cougaar104")
	super(run)
        @run = run
        @dbUser                = dbUser
        @dbHost                = dbHost
        @dbPassword            = dbPassword
        @db                    = db
      end

      def policyFileName
        File.join("#{@staging}", "policies")
      end

      def isDelta
        false
      end

      def calculatePolicies
        debug"calculating policies"
        `rm -rf #{@staging}`
        Dir.mkdir(@staging)
        p = buildInitialUrPolicies(@run, @dbUser, @dbHost, @dbPassword, @db)
        p.wellDefined?
        debug"writing policies #{@staging}"
        p.writePolicies(policyFileName())
        debug "policies written"
      end

      def perform
        calculatePolicies
        compilePolicies
      end
    end

    class InstallURPolicies < Cougaar::Actions::GeneratePoliciesAction
      def initialize(run, wait = false, skip = [])
	super(run)
        @run = run
        @wait = wait
        @skipEnclaves          = skip
        #@staging = File.join(CIP, "workspace", "URPolicies")
        debug("enclaves to skip = #{skip}")
      end

      def policyFileName
        File.join("#{@staging}", "policies")
      end

      def isDelta
        true
      end

      def perform
        commitPolicies(true, @wait)
      end
    end

    class MigratePolicies < Cougaar::Actions::GeneratePoliciesAction
      def initialize(run, node, enclave)
        super(run)
        @run = run
        @node = node
        @enclave = enclave
        #@staging = File.join(CIP, "workspace", "URPolicies")
      end

      def policyFileName()
        @policyFileName = "#{@staging}/migrationPolicies"
      end

      def isDelta()
        false
      end

      def calculatePolicies
        `rm -rf #{@staging}`
        Dir.mkdir(@staging)
        @run.society.each_enclave do |enclave|
          File.open("#{policyFileName()}-#{enclave}", "w+") do |file|
            debug("writing file #{file}")
            file.write <<-EndOfSimplePolicies
#
# Declarations Section
#

#
# Each of the declarations that follow defines names of policy
# concepts.  These names are used for stating and reasoning about
# policy.  However, in order for these names to be understood by the
# Ultralog enforcers, we need a mapping file that tells how Ultralog
# names are translated into policy names.  
#
# The two exceptions to this scheme are 
#  1. message verbs which are declared in Ontology-EntityInstances.owl and 
#     don't need a mapping file, and
#  2. communities which are declared in Ontology-GroupInstances.owl
#     and don't need a mapping file.
# I haven't moved the verb declarations because it requires a hack
# which I am not yet happy with.  I haven't moved the community
# declarations because they may be going away and I am concerned that
# there might be a performance hit.
#

#
# The policy prefix is prepended to each of the policy names.  It can
# be used - if desired - to arrange that built policies reside in a
# subdirectory.
#
PolicyPrefix=%OwlBootPolicy


#
# The mapping file for the following KAoS policy names is OwlMapUserRole.
#

UserRole Administrator
UserRole CAAdministrator
UserRole General
UserRole Guest
UserRole Logistician
UserRole LogisticsViewer
UserRole MonitorManager
UserRole \"x#{enclave.capitalize}PolicyAdministrator\"
UserRole PolicyAdministrator
UserRole UserManager
UserRole SocietyAdmin

#
# The mapping file for the following KAoS policy names is OwlMapUri
#

Servlet TestUserPolicyServlet
Servlet AggegatorServlets
Servlet NCAServlets
Servlet SCmrmanagerServlets
Servlet DataGrabberServlet
Servlet CertReqServlet
Servlet CAReadServlet
Servlet CAWriteServlet
Servlet HierarchyServlet
Servlet LogInventoryServlet
Servlet \"#{enclave.capitalize}PolicyServlet\"
Servlet PolicyServlet
Servlet SocietyAdminServlet
Servlet UserManagerServlets
Servlet OtherServlets



#
# There are three mapping files for these declarations, 
#    OwlMapRoleAgent     - to get the role from the agent name
#    OwlMapRoleComponent - to get the role from the component name
#    OwlMapRoleUri       - to get the role from the URI
#

PlugInRole PolicyServlet
PlugInRole DomainManagerAgent

PlugInRole OpPlanPlugIn
PlugInRole OrgActivityAdd
PlugInRole OrgActivityQuery
PlugInRole OrgActivityQueryNoRead
PlugInRole OrgActivityChange
PlugInRole OrgActivityRemove
PlugInRole OrgActivityAll

#
# The mapping file for these declarations is OwlMapBlackboardObjects.
#

BlackBoardObject BlackboardOpPlanObject
BlackBoardObject SafeRelay
BlackBoardObject OrgActivity

#
# End of Declarations Section
#

#
# Now the Policies follow:
#


#
# Message Passing Policies
#
#     Note: Users of the message passing policy templates need not worry
#           about the policy assumptions because the policy templates
#           satisfy the assumptions. 
#
# Policy Assumptions:
#     1. Positive policies have priority two and can only involve the
#        sender and the receiver and the verb
#     2. Negative policies have priority three and do not involve the verb.
#
#
# Justification:
#    The message enforcer has two enforcement phases and both phases
#     make decisions based on incomplete information.  In order for
#     these enforcers to make valid decisions assumptions 1 & 2 are
#     necessary. 
#


Policy AllowCommunication#{enclave} = [
   MessageAuthTemplate
   Allow messages from members of $Actor.owl#Agent to
   members of $Actor.owl#Agent
]


Policy EncryptCommunication = [ 
  MessageEncryptionTemplate
  Require NSAApprovedProtection on all messages from members of 
  $Actor.owl#Agent to members of $Actor.owl#Agent
]


#
# Blackboard policies
#

Policy AllowBlackboard = [ 
   GenericTemplate
   Priority = 2,
   $Ultralog/UltralogActor.owl#UltralogPlugins is authorized to perform
   $Ultralog/UltralogAction.owl#BlackBoardAccess as long as
    the value of $Ultralog/UltralogAction.owl#blackBoardAccessObject
    is a subset of the complement of the set
     { $Ultralog/BlackboardObject#OrgActivity
#       $Ultralog/BlackboardObject#SafeRelay
        }
]

#Policy AllowBlackboardPolicyQuery = [ 
#   GenericTemplate
#   Priority = 2,
#   $Ultralog/UltralogActor.owl#UltralogPlugins is authorized to perform
#   $Ultralog/UltralogAction.owl#BlackBoardAccess as long as
#    the value of $Ultralog/UltralogAction.owl#blackBoardAccessObject
#    is a subset of the set
#     { $Ultralog/Names/EntityInstances.owl#OrgActivity
#       $Ultralog/Names/EntityInstances.owl#SafeRelay }
#    and the value of $Ultralog/UltralogAction.owl#blackBoardAccessMode
#    is a subset of the set
#     { $Ultralog/Names/EntityInstances.owl#BlackBoardAccessQuery 
#       $Ultralog/Names/EntityInstances.owl#BlackBoardAccessRead }
#]


#Policy PolicyBlackboardServlet = [
#   BlackboardTemplate
#   A PlugIn in the role PolicyServlet can Add, Remove, Change
#   objects of type SafeRelay
#]

#Policy BlackboardDomainManager = [
#   BlackboardTemplate
#   A PlugIn in the role DomainManagerAgent can Add, Remove, Change
#   objects of type SafeRelay
#]


Policy OrgActivityAdd = [
   BlackboardTemplate
   A PlugIn in the role OrgActivityAdd can Add objects of type OrgActivity
]

Policy OrgActivityChange = [
   BlackboardTemplate
   A PlugIn in the role OrgActivityChange can Change, Query objects
   of type OrgActivity
]

Policy OrgActivityQuery = [
   BlackboardTemplate
   A PlugIn in the role OrgActivityQuery can Query objects of type OrgActivity
]

Policy OrgActivityRemove = [
   BlackboardTemplate
   A PlugIn in the role OrgActivityRemove can Remove, Query objects 
   of type OrgActivity
]

Policy OrgActivityAll = [
   BlackboardTemplate
   A PlugIn in the role OrgActivityAll can Add, Change, Query, Remove
   objects of type OrgActivity
]



#
# Servlet Policies
#
#     Note: Users of the servlet policy templates need not worry
#           about the policy assumptions because the servlet policy
#           templates satisfy the assumptions.
#
# Policy Assumptions:
#
#     1. Positive policies have priority two and can only involve the
#        set of users accessing the servlet and the name of the
#        servlet being accessed.
#     2. Negative policies have priority three.
#     3. Negative policies involving the authentication scheme
#        cannot involve the users.  One can only have negative
#        policies involving the user and a particular servlet in the
#        case that the policies require authentication scheme for
#        that servlet that actually identifies a user (e.g. not 
#        NoAuth or NoAuthSSL).
#     4. Policies only require Audit.  E.g. positive polices do not
#        involve audit and no policy states that audit is illegal.
#
# Justification:
#    The Servlet enforcer has two enforcement phases and the first
#     phase uses incomplete information. In order for the first phase to make
#     valid decisions assumptions 1 & 2 are necessary.  Assumption
#     three is a detail based on how mediation is performed.  A less
#     efficient mechanism would not need this assumption.
#

Policy UnrestServlet = [ 
   GenericTemplate
   Priority = 2,
   $Actor.owl#Person is authorized to perform
   $Ultralog/UltralogAction.owl#ServletAccess as long as
    the value of $Ultralog/UltralogAction.owl#accessedServlet
    is a subset of the set { $Ultralog/Names/EntityInstances.owl#OtherServlets 
                             $Ultralog/Names/EntityInstances.owl#CAReadServlet 
                             $Ultralog/Names/EntityInstances.owl#CertReqServlet }
]

#
# Only require audit on CAReadServlet and CertReqServlet because
#  1. this is a common event so it allows people to see audit
#  2. I can turn on other audits in other audit experiments.
#

Policy RequireAudit = [
   AuditTemplate
   Require audit for all accesses to all servlets
]

Policy PolicyServlet#{enclave.capitalize} = [
  ServletUserAccessTemplate
  A user in role \"x#{enclave.capitalize}PolicyAdministrator\" can access a servlet 
  named \"#{enclave.capitalize}PolicyServlet\"
]

Policy PolicyServlet#{enclave.capitalize}Auth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named \"#{enclave.capitalize}PolicyServlet\"
]

Policy PolicyServlet  = [ 
  ServletUserAccessTemplate
  A user in role PolicyAdministrator can access a servlet 
  named PolicyServlet
]

Policy PolicyServletAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named PolicyServlet
]

Policy TestPolicyServlet  = [ 
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named TestUserPolicyServlet
]
Policy TestPolicyServletAuth  = [ 
      ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named TestUserPolicyServlet
]

Policy SCmrManagerAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named SCmrmanagerServlets
]

Policy SCmrManager  = [ 
  ServletUserAccessTemplate
  A user in role MonitorManager can access a servlet named SCmrmanagerServlets
]

Policy NCAServlet = [
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named NCAServlets
]

Policy NCAServletAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named NCAServlets
]

Policy LogisticianAgg = [
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named AggegatorServlets
]

Policy LogisticianAggAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named AggegatorServlets
]

Policy LogisticianViewAgg = [
  ServletUserAccessTemplate
  A user in role LogisticsViewer can access a servlet named AggegatorServlets
]

Policy LogisticianViewAggAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named AggegatorServlets
]

Policy UserAdminServlets = [
  ServletUserAccessTemplate
  A user in role UserManager can access a servlet named UserManagerServlets
]

Policy UserAdminServletsAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named UserManagerServlets
]

Policy LogisticianInventory = [
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named LogInventoryServlet
]

Policy LogisticianInventoryAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named LogInventoryServlet
]

Policy LogisticsViewerInventory = [
  ServletUserAccessTemplate
  A user in role LogisticsViewer can access a servlet named LogInventoryServlet
]

Policy LogisticsViewerInventoryAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named LogInventoryServlet
]

Policy LogisticianHierarchy = [
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named HierarchyServlet
]

Policy LogisticianHierarchyAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named HierarchyServlet
]

Policy LogisticsViewerHierarchy  = [
  ServletUserAccessTemplate
  A user in role LogisticsViewer can access a servlet named HierarchyServlet
]

Policy LogisticsViewerHierarchyAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named HierarchyServlet
]

Policy CertWrite  = [
  ServletUserAccessTemplate
  A user in role CAAdministrator can access a servlet named CAWriteServlet
]

Policy CertWriteAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named CAWriteServlet
]

Policy SocietyAdmin = [
  ServletUserAccessTemplate
  A user in role SocietyAdmin can access a servlet named SocietyAdminServlet
]

Policy SocietyAdminAuth  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named SocietyAdminServlet
]

Policy AllowWhitePagesUpdate = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is  authorized to perform
  $Ultralog/UltralogAction.owl#WPUpdateSelf
 ]

Policy AllowWhitePagesLookup = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is  authorized to perform
  $Ultralog/UltralogAction.owl#WPLookup
 ]

Policy AllowWhiteForward = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is  authorized to perform
  $Ultralog/UltralogAction.owl#WPForward
 ]


Policy AllowRegistration = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is authorized to perform
  $DomainManagementAction.owl#RegisterAction
  as long as the value of
  $Action.owl#performedBy is a subset of the set

  $Actor.owl#Agent
 ]

Policy AllowCommunityAccess = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is  authorized to perform
  $Ultralog/UltralogAction.owl#CommunityAction
 ]

          EndOfSimplePolicies
          end
        end
      end

      def perform
        calculatePolicies
        commitPolicies(false, true)
      end
    end


    class MoveNodeGuard < Cougaar::Action
      def initialize(run, node, enclave)
        super(run)
        @run = run
        @node = node
        @enclave = enclave
      end

      def perform()
        web = SRIWeb.new()
        @nodeagent = getAgentByName(@node)
        web.getHtml(@nodeagent.uri + "/changePolicyManager?" +
                                   getPolicyAgent(@enclave).name + ":" +
                                   getPolicyDomain(@enclave))
      end

      def getPolicyAgent(enclave)
        policyAgent = nil
        @run.society.each_enclave_agent(enclave) do |agent|
          agent.each_facet(:role) do |facet|
            if facet[:role] == $facetPolicyManagerAgent then
              policyAgent = agent
            end
          end
        end
        policyAgent
      end
      
      def getPolicyDomain(enclave)
        enclave.capitalize + "Domain"
      end

      def getAgentByName(aname)
        @run.society.each_agent(true) do |agent|
          if agent.name == aname then
            return agent
          end
        end
        nil
      end
    end


  end
end
