##
#  <copyright>
#  Copyright 2003 SRI International
#  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the Cougaar Open Source License as published by
#  DARPA on the Cougaar Open Source Website (www.cougaar.org).
#
#  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
#  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
#  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
#  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
#  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
#  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
#  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  PERFORMANCE OF THE COUGAAR SOFTWARE.
# </copyright>
#


# Note:  This file contains two classes: CaDomain and CaDomains.
# CaDomains is a container for CaDomain instances. It is a singleton,
# so instantiation should be with CaDomains.instance (not CaDomains.new).
#
# CaDomain contains a name, signer (the signing agent), cadn,
# the parentDomain (usually the root ca domain) and corresponding
# childrenDomain.
#
# expectedEntities is a collection of entity names associated with this
# domain.  This is set by calling cadomain.ensureExpectedEntities. It is
# a singleton method, so it only needs to be called.


require 'lib/scripting'
require 'singleton'

module Cougaar
  module Model
    
    class Agent
      def caDomains
        node.caDomains
      end
      def distinguishedName
        caDomains[0].distinguishedNames[name]
      end
    end
    
    class Node
      attr_accessor :caDomains
      def caDomains
        CaDomains.instance.ensureExpectedEntities
        return @caDomains
      end
      def distinguishedName
        caDomains[0].distinguishedNames[name]
      end
    end
    
  end
end


#-------------------------------------------


class CaDomain
  attr_accessor :name            # name of the domain
  attr_accessor :signer          # CaManager signer
  attr_accessor :cadn            # CN=Root_CA, OU=Root, O=DLA ...
  attr_accessor :distinguishedNames  # {"NCA" => "SHA-b6128bb426aca3ecdd75281d7d70ddfe7104a652", ...}
  attr_accessor :parentDomain    # usually the root ca domain
  attr_accessor :childrenDomains
  attr_accessor :expectedEntities   # entities found in the society files
  attr_accessor :expectedWpEntities # entities found in the society files
  attr_accessor :actualEntities     # agents found on the certificateListing
  
  # todo need to clear caches when new run.count
  
  # expectedEntities is set in CaDomains.
  # actualEntities and wpEntities is set in this class.
  
  def initialize(domainName)
    @name = domainName
    @agent = nil
    @cadn = ''
    @parentDomain = nil
    @childrenDomains = []
    @expectedEntities = []
    @expectedWpEntities = []
    @actualEntities = []
    Dir.mkdir('pems') unless File.exists?('pems')
  end
  
  def node
    signer.node
  end
  
  def to_s
    agentName = parentDomainName = ''
    parentDomainName = parentDomain.name if parentDomain
    if signer
      agentName = signer.name
      nodeName = signer.node.name
    end
     "   CaDomain name=#{@name}\n  agent=#{agentName}\n  node=#{nodeName}\n  CADN=#{@cadn.as_string}\n  parentDomain=#{parentDomainName.as_string}\n  expectedEntities=#{@expectedEntities.as_string}\n  actualEntities=#{@actualEntities.as_string}\n  childrenDomains=#{childrenDomains.collect {|domain| domain.name}.as_string}\n"
  end
  
  
  # ------------ helper methods
  
  # Gets the actualEntities from the /CA/CertificateList page
  def getActualEntities
    # don't make this a singleton method because it may change over the
    # lifetime of the society.

    # Old servlet
    #validPattern = /distinguishedName" value="([^"]*).{1,180}">CN=([^,]*).{1,80}<TD>VALID.{1,150}<TD>CN=([^,]*)/m
    #revokedPattern = /\">CN=([^,]*).{1,80}<TD>REVOKED.{1,25}<TD>CN=([^,]*)/m
    #                                       SHA-....           CertLogistician
    validPattern = /distinguishedName" value="([^"]*).{1,180}">(CN=([^,]*)[^<]{1,110}).{0,35}<[tT][dD]>VALID/m
    revokedPattern = /\">CN=([^,]*).{1,80}<[tT][dD]>REVOKED.{1,250}<[tT][dD]>CN=([^,]*)/m
    url = "#{signer.uri}/CA/CertificateList"
    if @cadn == ''
      response = getHtml(uri)
#puts "in getActualEntites"
#puts response.code
#puts response.body
      @cadn = response.body.scan(/option value="([^"]*)/)[0][0]
    end
    # example: Enclave3_CA
    cadnName = @cadn.split(",")[0].split("=")[1]
    params = ["cadnname=#{cadnName}"]
    response = getHtml(url + "?" + params.join("&"))
#puts "in getActualEntites 2"
#puts "#{url}, #{response.code}"
#puts response.body
    scanResult = response.body.scan(validPattern)
    entities = scanResult.collect {|i| i[2]}
#puts entities.sort
#puts scanResult.collect {|i| i[0]}.sort
    @distinguishedNames = {}
    @cadnNames = {}
    scanResult.each {|i| @distinguishedNames[i[2]] = i[0]}
    scanResult.each {|i| @cadnNames[i[2]] = i[1]}
    @actualEntities = entities.sort
    return @actualEntities
  end
  
  def revokeUserCert(name)
    puts "revoking certificate #{name}" if $VerboseDebugging
    getActualEntities
    dn = @distinguishedNames[name]
    unless dn
      logInfoMsg "Couldn't find the distinguished name for #{name}, unable to revoke user on CA #{@name}"
      return false
    end
    params = ["distinguishedName=#{CGI.escape(@distinguishedNames[name])}",
              "cadnname=#{CGI.escape(@cadn)}"]
    url = signer.uri + '/CA/RevokeCertificateServlet'
    w = SRIWeb.new
    response = w.postHtml(url, params)
    return response.code == 200
  end
  
  def createUserCert(userName)
    cert = generateLocalKey(userName)
    # this file isn't used, but may be useful for debugging purposes
    f=File.new("pems/#{name}#{userName}_localCert.pem", "w")
    f.puts cert
    f.close
    signedCert = getSignedCert(cert)

    # Save the cert to a file
    certFile = File.new("pems/#{name}#{userName}_cert.pem", "w")
    certFile.puts signedCert
    certFile.close
  end
  
  def generateLocalKey(userName)
    createOpenSSLParamFile userName
    puts "params file: #{File.readlines('params').join('')}" if $ShowUserCreation
    cert = %x{openssl req -nodes -new -keyout pems/"#{name}#{userName}"_key.pem -days 365 < params 2>/dev/null}
    File.delete("params")
    
    return cert
  end
  
  def getSignedCert(cert)
    # Create request parameters
    params = []
    params << "dnname=#{CGI.escape(cadn)}"
    params << "pkcs=pkcs10"
    params << "pkcsdata=#{CGI.escape(cert)}"
    params << "replyformat=html"
    
    url = signer.uri + '/CA/CertificateSigningRequest'
    if $ShowUserCreation
      puts "params = #{(params.collect {|p| CGI.unescape(p)}).join("&")}"
      puts "getting signedCert from url=#{url} ..."
    end
    
    # Get the certificate signed and remove html tags
    response = postHtml url, params

    if $ShowUserCreation
      puts "signedCert.body"
      puts response.body
    end
    signedCert = CGI.unescapeHTML(response.body)
    signedCert = response.body
#puts "signedCert = [#{signedCert}]"
    
    array = signedCert.split('<br>')
    array[0] = array[0].split[1] + ' CERTIFICATE-----'
    array = array[0..-2] << ''
    signedCert = array.join("\n")
    
    #puts "[#{signedCert}]"
    
    return signedCert
  end
  
  # Generates a local key/cert, but does not get a signed cert from cougaar
  def createBogusCert(userName)
    userName = 'bogus_'+userName
    createOpenSSLParamFile(userName)
      %x{openssl req -nodes -new -keyout pems/"#{name}#{userName}"_key.pem -x509 -out "#{name}#{userName}_cert.pem" -days 365 < params 2>/dev/null}
    File.delete("params")
  end
  
  
  # Creates the parameter file used as input to openssl
  #    which will generate a certificate request
  def createOpenSSLParamFile(userName)
    #CN=Enclave1_CA, OU=Enclave1, O=DLA, L=San Francisco, ST=CA, C=US, T=ca
    userDomain = signer.userDomain.name
    orgUnitName = cadn.scan(/CN=(.*), OU=/)[0][0]
    orgName = cadn.scan(/, OU=(.*), O=/)[0][0]+"CA"
    city = cadn.scan(/, L=(.*), ST=/)[0][0]
    state = cadn.scan(/, ST=(.*), C=/)[0][0]
    country = cadn.scan(/, C=(.*), T=/)[0][0]
    #               US          VA      Arlington  Cougaar     Ultralog
#    parameters = "#{country}\n#{state}\n#{city}\n#{orgName}\n#{orgUnitName}\n#{userDomain}-#{userName}\n\n\n\n"
    parameters = "#{country}\n#{state}\n#{city}\n#{orgName}\n#{orgUnitName}\n#{userName}\n\n\n\n"
    puts "parameters: #{parameters}" if $ShowUserCreation
    
    # Save the parameters to a file for redirection into openssl
    paramFile = File.new("params", "w")
    paramFile.puts parameters
    paramFile.close
  end
  
  
  # -------------  Validation Methods
  
  def validateCertificateList
    agentList = nil
    agentList = getAgentList
    if actualEntities and expectedEntities
      # These variables (i.e., extras) are from the perspective of the cert list
      extras = actualEntities - expectedEntities
      missing = expectedEntities - actualEntities
      dead = missing - agentList
      stillMissing = missing - dead
      if extras==[] and missing==[]
        saveResult(true, '5h101-106,5i101-104,5k101,5k111', "CA domain #{name} contains the correct agents.")
      else
        if missing != []
          summary "CA #{signer.name}'s cert listing is missing agents:"
          summary "   "+missing.as_string
          if dead != []
            summary "   These agents are dead:"
            summary "   "+dead.as_string
          end
          if stillMissing == []
            saveResult(true, '5h101-106,5i101-104,5k101,5k111', 'All active entities are listed on the CA.')
          else
            summary "   So these agents are missing from the CA:"
            summary "   "+stillMissing.as_string
            saveResult(false, '5h101-106,5i101-104,5k101,5k111', 'Some entities are missing from the CA')
            success = false
          end
        end
      end
    end
    if extras != []
      if missing==[]
        summary "CA domain #{name}'s cert listing is complete, but has extra agents:"
      else
        summary "   but the cert listing has extra agents:"
      end
      summary "   "+extras.as_string
    end
    return [expectedEntities.size-stillMissing.size, expectedEntities.size]
  end
  
  def validateWpEntities(wpEntities)
    missing = expectedWpEntities - wpEntities
    if missing.size == 0
      saveResult true, "5i105,5k109", "There were no missing wp entities on CA domain #{name}"
    else
      saveResult false, "5i105,5k109", "Missing wp entities on CA domain #{name}: #{missing.as_string}"
    end
    [expectedWpEntities.size-missing.size, expectedWpEntities.size]
  end
  
  
  # returns list of agents at $NCA/agents?scope=.
  def getAgentList
    agentListHtml = getHtml("#{run.society.agents['NCA'].uri}/agents?scope=.", 3.minutes)
    agents = agentListHtml.body.to_s.scan(/list\">(.*)<\/a>/).sort
    @agentList = agents.collect {|a| a[0]}
  end
  
  def run
    getRun
  end
end


#----------------------------------------


class CaDomains
  include Singleton
  include Enumerable
  
  attr_accessor :domains
  
  def initialize
    super
    @runcount = -1
  end
  
  
  def run
    getRun
  end
  
  def [](domainName)
    ensureDomains
    unless @domains[domainName]
      @domains[domainName] = CaDomain.new(domainName)
    end
    return @domains[domainName]
  end
  
  def domains
    ensureDomains
    return @domains
  end
  
  def each(&block)
    ensureDomains
    domains.each do |domainName, caDomain|
      yield domainName, caDomain
    end
  end
  
  def ensureDomains
    if run.count != @runcount
      @runcount = run.count
      @domains = {}
    end
  end
    
  def printIt
    puts
    each do |domainName, caDomain|
      puts caDomain
      puts
    end
    puts "wpEntities = #{@wpEntities.as_string}"
  end
    
   # this method compares the expected with the actual and wp
   def validateDomainEntities
      certTotals = validateActualEntities
      wpTotals = validateWpEntities
      successRatio = (certTotals[0]+wpTotals[0]) / (certTotals[1]+wpTotals[1])
      summary "The success ratio is #{successRatio}"
      return successRatio
   end

   def validateActualEntities
      ensureExpectedEntities
      certSuccess = []
      certSuccess = collect do |domainName, caDomain|
         caDomain.getActualEntities
         caDomain.validateCertificateList
      end
      certTotals = certSuccess.injectIt([0,0]) {|x,y| [x[0]+y[0], x[1]+y[1]]}
      summary "**** #{certTotals[0]} out of #{certTotals[1]} certs were found ****"
      return certTotals
   end

   def validateWpEntities
      wpSuccess = []
      allExpectedEntities = []
      wpEntities = getWpEntities
      wpSuccess = collect do |domainName, caDomain|
         allExpectedEntities += caDomain.expectedWpEntities
         caDomain.validateWpEntities(wpEntities)
      end
      missing = wpEntities - allExpectedEntities
      summary "The white pages contains extra certificates: #{missing.as_string}" if missing
      wpTotals = wpSuccess.injectIt([0,0]) {|x,y| [x[0]+y[0], x[1]+y[1]]}
      summary "**** #{wpTotals[0]} out of #{wpTotals[1]} certs were found on wp ****"
      return wpTotals
   end


=begin
      if success
         summary "Success:  All CAs have the correct agents."
      else
         summary "Failure:  Not all CAs have the correct agents."
      end
      return success
=end


   def ensureExpectedEntities
      # We only need to run this once because it won't change.
      ensureDomains
      getExpectedEntities unless domains.keys.size > 0
   end

   # Gets the expectedEntities from the loaded society file.
   def getExpectedEntities
      findCAnodes
      associateAgentsWithCaManagers
      addExpectationForChildrenDomains
      makeExpectedWpEntities
      @expectedEntities
   end

   # Get the white pages entities which have a certificate from the /wp page
      def getWpEntities
        ensureExpectedEntities
        url = getNameServer.uri + '/wp?action=recursive_dump&useCache=true&timeout=&async=false&limit=&name='
        response = getHtml(url)
        wpEntities = parseWp(response.body)
        @wpEntities = wpEntities
        return wpEntities
      end
      
      def getNameServer
        run.society.each_node do |node|
          node.each_facet('role') do |facet|
            if facet['role'] = 'NameServer'
              return node
            end
          end
        end
        raise "Couldn't find NameServer facet"
      end
      
      def getActualEntities
        ensureExpectedEntities
        each do |domainName, caDomain|
          caDomain.getActualEntities
        end
      end
      
      # Find the CA nodes [example: (ROOT|FWD|REAR|CONUS|TRANS)-CA-NODE]
      def findCAnodes
        run.society.each_host do |host|
          host.each_node do |node|
            components = node.getComponentsMatching(/security.certauthority.ConfigPlugin/)
            
            components.each do |component|
              # 1st arg = 'CN=RootCA, OU=Root, O=DLA ...
              cadn = component.arguments[0].to_s
              caDomainName = cadn.split(',')[0].split('=')[1]
              managerAgent = findNodeCaManager node
              domain = self[managerAgent.name]
              domain.name = caDomainName
              domain.signer = managerAgent
              domain.cadn = cadn
              # 3rd arg = 'sv024:RootCaManager:8800:9800'
              if component.arguments.size >= 3
                parentStr = component.arguments[2].to_s
                parentCaManagerName = parentStr.split(':')[1]
                domain.parentDomain = self[parentCaManagerName]
                self[parentCaManagerName].childrenDomains << domain
              end
              node.caDomains = [] unless node.caDomains
              node.caDomains << domain
            end
          end
        end
      end
      
      def findNodeCaManager(node)
        node.each_agent do |agent|
          components = agent.getComponentsMatching /certauthority.CaServletComponent/
          components.each do |component|
            if component.arguments[0].to_s =~ /servlet.CertificateList/
              return agent
            end
          end
        end
        logWarningMsg "Missing certauthority.CaServletComponent for node #{node.name}"
        nil
      end
      
      # Figure out which agents go with which ca domains
      def associateAgentsWithCaManagers
        # Find the society agents which belong to each CA node
        run.society.each_host do |host|
          host.each_node do |node|
            # list of agents which should have certificates on this node
            entities = node.agents.collect {|agent| agent.name}
            entities << node.name
            # for tomcat, assumes society is running https
            entities << host.name
            
            # all nodes except (ROOT|FWD|REAR|CONUS|TRANS)-CA-NODEs have this
            components = node.getComponentsMatching(/crypto.AutoConfigPlugin/)
            if components == []
              # this must be a CA node.
              node.caDomains.each do |caDomain|
                #caManager = caDomain.signer.name
                entities << caDomain.name
                #caDomain = self[caManager]
                #node.caDomain = caDomain
                caDomain.expectedEntities = (caDomain.expectedEntities + entities).sort
              end
            else
              # 1st arg = 'sv041:ConusEnclaveCaManager:8810:9810'
              components.each do |component|
                castr = component.arguments[0].to_s
                caManager = castr.split(":")[1]
                caDomain = self[caManager]
                node.caDomains = [] unless node.caDomains
                node.caDomains << caDomain
                caDomain.expectedEntities = (caDomain.expectedEntities + entities).sort
              end
            end
          end # each_node
        end # each_host
      end
      
      # A parent CA domain (such as RootCA) should expect to have a cert for its
      # children.
      def addExpectationForChildrenDomains
        each do |domainName, caDomain|
          entities = caDomain.expectedEntities
          caDomain.childrenDomains.each do |childDomain|
            entities << childDomain.name
          end
          caDomain.expectedEntities = entities.sort
        end
      end
      
      def parseWp(content)
        pat = wpPattern
        
        rows = []
        m = pat.match(content)
        if m
          # [name, type, uri, cert]
          # ex: [REAR-B-NODE, certificate, cert://REAR-B-NODE, org.cougaar.core.security.naming.NamingCertEntry@b6c33027]
          rows << [m[2], m[3], m[4], m[5]]
          while m = pat.match(m.post_match)
            rows << [m[2], m[3], m[4], m[5]]
          end
        end
        certs = rows.select {|row| row[3] != 'null_cert'}
        certs = certs.collect {|cert| cert[0]}
        return certs
      end
      
      def wpPattern
        pre = "<td[^>]*>"
        mid = "([^<]*)"
        post = "</td>"
        td = pre + mid + post
        # Note: there is an extra </td> in each row
        all = "<tr>"+td+td+td+td+td+"</td></tr>"
        return Regexp.new(all)
      end
      
      # the white page entities should be the same as the certificate listing
      # entities minus the hosts and CAs.
      def makeExpectedWpEntities
        hostNames = []
        run.society.each_host {|host| hostNames << host.name}
        caNames = []
        each {|name, ca| caNames << ca.name}
        each do |domainName, caDomain|
          caDomain.expectedWpEntities = caDomain.expectedEntities - hostNames - caNames
        end
      end
      
      def CaDomains.domainsWithEntity(entityName, retrieveActualEntities=true)
        instance.domainsWithEntity entityName, retrieveActualEntities
      end
      def domainsWithEntity(entityName, retrieveActualEntities=true)
        #ensureExpectedEntities
        select do |domainName, caDomain|
          caDomain.getActualEntities if retrieveActualEntities
          caDomain.actualEntities.detect {|name| name == entityName}
        end
      end
      
    end # class CaDomains
    
    
    
    
    #end # Model
    #end # Cougaar
    
    
    #----------------------------------------
    
=begin

   def getRootCertificateNode
      getRun.society.each_node do |node|
         node.each_facet do |facet|
            if facet['role']=='RootCertificateAuthority'
               return node
            end
         end
      end
      logWarningMsg "There doesn't seem to be a facet with 'RootCertificateAuthority' as role.  Will try using 'ROOT-CA-NODE' for the root CA node."
      return getRun.society.nodes['ROOT-CA-NODE']
   end

   # The following code creates hashes based on time for UserTry and Idmef
   def addUserTry(time, usertry, returnStatusCode)
      ensureUserTry
      @userTries[time] = [usertry, returnStatusCode]
   end
   def removeUserTry(time)
      ensureUserTry
      @userTries.delete(time)
   end
   def ensureUserTry
      if not defined? @userTries
         @userTries = {}
      end
   end

   def addIdmef(time, event)
      ensureIdmef
      @idmefs[time] = event
   end
   def removeIdmef(time)
      ensureIdmef
      @idmefs.delete(time)
   end
   def forEachIdmef(&block)
      ensureIdmef
      @idmefs.each do |key, value|
         yield key, value
      end
   end
   def ensureIdmef
      if not defined? @idmefs
         @idmefs = {}
      end
   end
=end
    
