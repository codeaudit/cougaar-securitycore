#!/usr/bin/ruby

require 'cougaar/communities'
require 'ultralog/enclaves'
require 'security/lib/jar_util'
require 'security/lib/policy_util'
require 'security/lib/common_security_rules'


module Cougaar
  module Actions
    class BuildPolicies < Cougaar::Action
      def perform
        init()
        buildUserRoleMap()
        buildUriMap()
        buildOwlBootPolicyList()
        compilePolicies()
        packageAndSignJar()
        deleteStagingDir()
      end

      def init
        @cip = ENV['COUGAAR_INSTALL_PATH']
        @stagingdir = "/tmp/BootPolicies-#{rand(1000000)}"
        @policyFile = "#{@stagingdir}/OwlBootPolicyList"
        @policies = []
        @enclaves = []
        run.society.each_enclave { |e| @enclaves.push(e) }

        Dir.mkdir(@stagingdir)
      end

      def compilePolicies
        output = policyUtil("--maxReasoningDepth 150 build --info #{@policyFile}",
                            nil, "#{@stagingdir}")
# some hacky attempts to determine that there were no errors
#  errors are pretty much fatal!  Running the society if the following fails
#  is probably a waste of time
        @policies.each do |policy|
          if output.index("Built Policy: #{"OwlBootPolicy" + policy}") == nil then
            puts output
            puts "Fatal error making policies"
            puts "Possibly policy #{policy} is bad"
            puts "try cd #{stagingDir}; policyUtil build --info OwlBootPolicyList to see what is happening"
            raise "Fatal Policy Build Error"
          end
        end
      end # def compilePolicies

      def packageAndSignJar
        jarFile="#{@cip}/configs/security/bootpolicies.jar"
        signingKeystore="#{@cip}/configs/security/bin/signingCA_keystore"
        begin 
          File.delete(jarFile)
        rescue
          # its ok - problems on the next one aren't.
        end
        `cd #{@stagingdir} && jar cf #{jarFile} .`
        `jarsigner -keystore #{signingKeystore} -storepass keystore #{jarFile} privileged`
      end # def packageAndSignJar


      def deleteStagingDir
        `rm -rf #{@stagingDir}`
      end # def deleteStagingDir
#
# The only things below are buildUserRoleMap, buildUriMap,
# buildOwlBootPolicyList. This is hacky but each of these routines simply
# write a bunch of data to the three files, OwlMapUserRole, OwlMapUri
# and OwlBootPolicyList.
#

      def buildUserRoleMap
        File.open("#{@stagingdir}/OwlMapUserRole" ,"w") { |file|
          file.write <<END
.*\\\\Administrator Administrator
.*\\\\CAAdministrator CAAdministrator
.*\\\\General General
.*\\\\Guest Guest
.*\\\\Logistician Logistician
.*\\\\LogisticsViewer LogisticsViewer
.*\\\\MonitorManager MonitorManager
#{@enclaves.collect {|e| "#{e.capitalize}UserDomainComm\\\\PolicyAdministrator x#{e.capitalize}PolicyAdministrator"}.join("\n")}
.*\\\\PolicyAdministrator PolicyAdministrator
.*\\\\UserManager UserManager
.*\\\\SocietyAdmin SocietyAdmin
END
        }
      end # def buildUserRoleMap


      def buildUriMap
        File.open("#{@stagingdir}/OwlMapUri","w") { |file|
          file.write <<END
#
# This file has the form:
#    (Ultra*Log Policy Pattern) Space (KAoS Name)
# The Ultra*Log Policy Pattern has the same syntax as the ones in the
# xml policies.  This is a very rigid pattern - the method that reads
# this file has no smarts.
#
# When edditing this file you need to be sure that each KAoS name in
# this file also appears in the Ontology-EntityInstances.daml file as
# a ultralogEntity:Servlet.
#
# Start with the servlets that are specific to a particular agent.
# Some how it seems if we know the agent then the pattern is more
# specific.
#
#commented out because of FreezeSociety
#/\\$AGG-Agent/aggregator AggegatorServlets
#/\\$AGG-Agent/aggregatorkeepalive AggegatorServlets
# 
# temporarily turn these off for ACME
/\\$NCA/glsinit NCAServlets
/\\$NCA/glsreply NCAServlets
/\\$NCA/editOplan NCAServlets
# 
/\\$SCmrmanager/.* SCmrmanagerServlets
#
# Servlets with no particular agent.
#
#  datagatherer is not included so the automated tests work...
#/\\$.*/datagatherer AggegatorServlets
#/\\$.*/log_inventory AggegatorServlets
#
/\\$.*/CA/CertificateSigningRequest CertReqServlet
/\\$.*/CA/BrowserSigningRequest CertReqServlet
#
/\\$.*/CA/Index CAReadServlet
/\\$.*/CA/Browser CAReadServlet
/\\$.*/CA/Main CAReadServlet
/\\$.*/CA/CertificateList CAReadServlet
/\\$.*/CA/CertificateDetailsServlet CAReadServlet
/\\$.*/CA/DownloadCertificateServlet CAReadServlet
/\\$.*/CA/PendingCertificateServlet CAReadServlet
/\\$.*/CA/PendingCertDetailsServlet CAReadServlet
/\\$.*/CA/ListCaKeysServlet CAReadServlet
/\\$.*/CA/ListSubordCaServlet CAReadServlet
# 
/\\$.*/CA/RevokeCertificateServlet CAWriteServlet
/\\$.*/CA/CreateCaKeyServlet CAWriteServlet
/\\$.*/CA/SubmitCaKeyServlet CAWriteServlet
/\\$.*/CA/ProcessPendingCertServlet CAWriteServlet
/\\$.*/CA/CaKeyManagement CAWriteServlet
#
#/\\$.*/hierarchy HierarchyServlet
# commented out because of FreezeSociety
#/\\$.*/log_inventory LogInventoryServlet
#
#{@enclaves.collect {|e| "/\\$#{e.capitalize}PolicyDomainManagerServlet/policyAdmin #{e.capitalize}PolicyServlet"}.join("\n")}
/\\$.*/policyAdmin PolicyServlet

#
/\\$.*/move SocietyAdminServlet
/\\$.*/load SocietyAdminServlet
/\\$.*/topology SocietyAdminServlet
#
/\\$.*/useradmin UserManagerServlets
/\\$.*/TestUserPolicy TestUserPolicyServlet

/\\$.*/.* OtherServlets
/.* OtherServlets

END
        }
      end # def buildUriMap

      def buildOwlBootPolicyList
        File.open(@policyFile,"w") { |file|
          file.write <<END
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
#{@enclaves.collect {|e| "UserRole \"x#{e.capitalize}PolicyAdministrator\"" }.join("\n")}
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
#{@enclaves.collect {|e| "Servlet \"#{e.capitalize}PolicyServlet\"" }.join("\n")}
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


Policy #{@policies.push("AllowCommunication").last()} = [
   MessageAuthTemplate
   Allow messages from members of $Actor.owl#Agent to
   members of $Actor.owl#Agent
]


Policy #{@policies.push("EncryptCommunication").last()} = [ 
  MessageEncryptionTemplate
  Require NSAApprovedProtection on all messages from members of 
  $Actor.owl#Agent to members of $Actor.owl#Agent
]


#
# Blackboard policies
#

Policy #{@policies.push("AllowBlackboard").last()} = [ 
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


Policy #{@policies.push("OrgActivityAdd").last()} = [
   BlackboardTemplate
   A PlugIn in the role OrgActivityAdd can Add objects of type OrgActivity
]

Policy #{@policies.push("OrgActivityChange").last()} = [
   BlackboardTemplate
   A PlugIn in the role OrgActivityChange can Change, Query objects
   of type OrgActivity
]

Policy #{@policies.push("OrgActivityQuery").last()} = [
   BlackboardTemplate
   A PlugIn in the role OrgActivityQuery can Query objects of type OrgActivity
]

Policy #{@policies.push("OrgActivityRemove").last()} = [
   BlackboardTemplate
   A PlugIn in the role OrgActivityRemove can Remove, Query objects 
   of type OrgActivity
]

Policy #{@policies.push("OrgActivityAll").last()} = [
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

Policy #{@policies.push("UnrestServlet").last()} = [ 
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

Policy #{@policies.push("RequireAudit").last()} = [
   AuditTemplate
   Require audit for all accesses to all servlets
]

#{@enclaves.collect {|e| 
"Policy #{@policies.push("PolicyServlet#{e.capitalize}").last()} = [
  ServletUserAccessTemplate
  A user in role \"x#{e.capitalize}PolicyAdministrator\" can access a servlet 
  named \"#{e.capitalize}PolicyServlet\"
]

Policy #{@policies.push("PolicyServlet#{e.capitalize}Auth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named \"#{e.capitalize}PolicyServlet\"
]
"}.join("\n")}

Policy #{@policies.push("PolicyServlet").last()}  = [ 
  ServletUserAccessTemplate
  A user in role PolicyAdministrator can access a servlet 
  named PolicyServlet
]

Policy #{@policies.push("PolicyServletAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named PolicyServlet
]

Policy #{@policies.push("TestPolicyServlet").last()}  = [ 
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named TestUserPolicyServlet
]
Policy #{@policies.push("TestPolicyServletAuth").last()}  = [ 
      ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named TestUserPolicyServlet
]

Policy #{@policies.push("SCmrManagerAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named SCmrmanagerServlets
]

Policy #{@policies.push("SCmrManager").last()}  = [ 
  ServletUserAccessTemplate
  A user in role MonitorManager can access a servlet named SCmrmanagerServlets
]

Policy #{@policies.push("NCAServlet").last()} = [
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named NCAServlets
]

Policy #{@policies.push("NCAServletAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named NCAServlets
]

Policy #{@policies.push("LogisticianAgg").last()} = [
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named AggegatorServlets
]

Policy #{@policies.push("LogisticianAggAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named AggegatorServlets
]

Policy #{@policies.push("LogisticianViewAgg").last()} = [
  ServletUserAccessTemplate
  A user in role LogisticsViewer can access a servlet named AggegatorServlets
]

Policy #{@policies.push("LogisticianViewAggAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named AggegatorServlets
]

Policy #{@policies.push("UserAdminServlets").last()} = [
  ServletUserAccessTemplate
  A user in role UserManager can access a servlet named UserManagerServlets
]

Policy #{@policies.push("UserAdminServletsAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named UserManagerServlets
]

Policy #{@policies.push("LogisticianInventory").last()} = [
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named LogInventoryServlet
]

Policy #{@policies.push("LogisticianInventoryAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named LogInventoryServlet
]

Policy #{@policies.push("LogisticsViewerInventory").last()} = [
  ServletUserAccessTemplate
  A user in role LogisticsViewer can access a servlet named LogInventoryServlet
]

Policy #{@policies.push("LogisticsViewerInventoryAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named LogInventoryServlet
]

Policy #{@policies.push("LogisticianHierarchy").last()} = [
  ServletUserAccessTemplate
  A user in role Logistician can access a servlet named HierarchyServlet
]

Policy #{@policies.push("LogisticianHierarchyAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named HierarchyServlet
]

Policy #{@policies.push("LogisticsViewerHierarchy").last()}  = [
  ServletUserAccessTemplate
  A user in role LogisticsViewer can access a servlet named HierarchyServlet
]

Policy #{@policies.push("LogisticsViewerHierarchyAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named HierarchyServlet
]

Policy #{@policies.push("CertWrite").last()}  = [
  ServletUserAccessTemplate
  A user in role CAAdministrator can access a servlet named CAWriteServlet
]

Policy #{@policies.push("CertWriteAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named CAWriteServlet
]

Policy #{@policies.push("SocietyAdmin").last()} = [
  ServletUserAccessTemplate
  A user in role SocietyAdmin can access a servlet named SocietyAdminServlet
]

Policy #{@policies.push("SocietyAdminAuth").last()}  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named SocietyAdminServlet
]

Policy #{@policies.push("AllowWhitePagesUpdate").last()} = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is  authorized to perform
  $Ultralog/UltralogAction.owl#WPUpdateSelf
 ]

Policy #{@policies.push("AllowWhitePagesLookup").last()} = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is  authorized to perform
  $Ultralog/UltralogAction.owl#WPLookup
 ]

Policy #{@policies.push("AllowWhiteForward").last()} = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is  authorized to perform
  $Ultralog/UltralogAction.owl#WPForward
 ]


Policy #{@policies.push("AllowRegistration").last()} = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is authorized to perform
  $DomainManagementAction.owl#RegisterAction
  as long as the value of
  $Action.owl#performedBy is a subset of the set

  $Actor.owl#Agent
 ]

Policy #{@policies.push("AllowCommunityAccess").last()} = [
  GenericTemplate
  Priority = 2,
  $Actor.owl#Agent is  authorized to perform
  $Ultralog/UltralogAction.owl#CommunityAction
 ]


END
        }
      end # def buildOwlBootPolicyList
    end # class BuildPolicies
  end # module Actions
end # module Cougaar
