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

# This section adds 'userAdminAgent' and 'caSignerAgent' methods to nodes
# and agents. These allow for finding agent responsible for this managing
# this agent's user domain and certificate signing.

require 'singleton'
require 'cgi'
require 'thread'
require 'security/lib/experimentFramework'

class UserClass
  attr_accessor :name, :passwd, :authreq, :firstname, :lastname, :roles
  attr_accessor :enableTime, :certOkWhenDisabled
  attr_accessor :mail
  
  def initialize(name='', passwd='', authreq="EITHER", firstname='', lastname='', roles=[])
    @name = name
    @passwd = passwd
    @authreq = authreq
    @firstname = firstname
    @lastname = lastname
    @roles = roles
    enable
  end
  
  def to_s
    "  UserClass name=#{@name}, passwd=#{@passwd.to_s}, authreq=#{@authreq}, enableTime=#{@enableTime}, certOk=#{certOkWhenDisabled.to_s}, roles=#{roles.as_string}"
  end

  def UserClass.premadeUser(userName)
    USER_COLLECTION.detect {|user| user.name==userName}
  end

  def enable
    @enableTime = '19700101000000Z'
  end

  def disable
    @enableTime = ''
  end
end

USER_COLLECTION = [
  # name, password, authreq, firstname, lastname, roles

  UserClass.new('CAndPLogistician', 'CAndPLogistician',
                'EITHER', 'certAndPwd', 'logistician', ['Logistician']),
  UserClass.new('CertLogistician', 'CertLogistician',
                'CERT', 'cert', 'logistician', ['Logistician']),
  UserClass.new('PasswordLogistician', 'PasswordLogistician',
                'PASSWORD', 'pwd', 'logistician', ['Logistician']),

  UserClass.new('DisabledLogistician', 'DisabledLogistician',
                'CERT', 'disabled', 'logistician', ['Logistician']),
  UserClass.new('DeletedLogistician', 'DeletedLogistician',
                'CERT', 'deleted', 'logistician', ['Logistician']),
  UserClass.new('RevokedLogistician', 'RevokedLogistician',
                'CERT', 'revoked', 'logistician', ['Logistician']),
  UserClass.new('RecreatedLogistician', 'RevokedLogistician',
                'CERT', 'recreated', 'logistician', ['Logistician']),
  UserClass.new('NotALogistician', 'NotALogistician',
                'CERT', 'notA', 'logistician', ['']),
  UserClass.new('OtherCert', 'OtherCert',
                'CERT', 'otherCert', 'logistician', ['']),

  # this user will be created at both fwd (access should be granted)
  # and conus (not granted).
  UserClass.new('FwdPolicyUser', 'FwdPolicyUser',
                'PASSWORD', 'fwd', 'policyUser', ['PolicyAdministrator']),
  UserClass.new('RearPolicyUser', 'RearPolicyUser',
                'PASSWORD', 'rear', 'policyUser', ['PolicyAdministrator']),
  UserClass.new('TransPolicyUser', 'TransPolicyUser',
                'PASSWORD', 'trans', 'policyUser', ['PolicyAdministrator']),
  UserClass.new('ConusPolicyUser', 'ConusPolicyUser',
                'PASSWORD', 'conus', 'policyUser', ['PolicyAdministrator']),
  UserClass.new('FwdPolicyUser2', 'FwdPolicyUser2',
                'PASSWORD', 'fwd', 'policyUser', ['PolicyAdministrator']),
  # this user will be created at conus and used to try to gain access
  # to the /policyAdmin servlet in fwd.  this role should be prevented
  # from being created.
  UserClass.new('R', 'R',
                'PASSWORD', 'fwd', 'policyUser', ['FwdUserDomainComm\FwdPolicyAdministrator']),


  #    UserClass.new("PolAdmin", "PolAdmin", "EITHER",
  #       "PolicyAdministrator", "SecureSociety", ["PolicyAdministrator"]),
  UserClass.new("FwdPolAdmin", "FwdPolAdmin", "EITHER",
                "PolicyAdministrator", "SecureSociety", ["PolicyAdministrator"]),
  UserClass.new("RearPolAdmin", "RearPolAdmin", "EITHER",
                "PolicyAdministrator", "SecureSociety", ["PolicyAdministrator"]),
  UserClass.new("UsrMngr", "UsrMngr", "EITHER",
                "UserManager", "SecureSociety", ["UserManager"]),
  UserClass.new("ALogistician", "ALogistician", "EITHER",
                "Logistician", "SecureSociety", ["Logistician"]),
  UserClass.new("LogViewer", "LogViewer", "EITHER",
                "LogisticsViewer", "SecureSociety",  ["LogisticsViewer"]),
  UserClass.new("Mover", "Mover", "EITHER",
                "Mover", "SecureSociety", ["SocietyAdmin"]),
  UserClass.new("CertAndPassUser", "CertAndPassUser", "EITHER",
                "CertAndPassUser", "SecureSociety",  ["Logistician"]),
  UserClass.new("CertUser", "CertUser", "CERT",
                "CertUser", "SecureSociety", ["Logistician"]),
  UserClass.new("Nobody", "Nobody", "EITHER",
                "Nobody", "SecureSociety",  []),
  UserClass.new("BadUser", "DontUseThis", "PASSWORD",
                "Bad", "User", ['PolicyAdminstrator', 'UserManager', 'Logisitician']),
  UserClass.new("BogusUser", "BogusUser", "EITHER",
                "Bad", "User", ['PolicyAdminstrator', 'UserManager', 'Logisitician']),
  UserClass.new("RearPolicyAdmin", "RearPolicyAdmin", "EITHER",
                "RearPolicyAdmin", "RearPolicyAdminLast", ['PolicyAdministration']),
  UserClass.new("ConusPolicyAdmin", "ConusPolicyAdmin", "EITHER",
                "ConusPolicyAdmin", "ConusPolicyAdminLast", ['PolicyAdministration']),

  UserClass.new("CertUser", "CertUser", "CERT",
                "CertUser", "SecureSociety", ["Logistician"]),
]


#-------------------------------------------------

class UserDomain

  def url
    #      @url = agent.uri+'/useradmin' unless @url
    @urll = agent.url+'/useradmin' unless @urll
    @urll
  end

  #--------- Query Methods ----------
  # returns a list of usernames
  def users
    searchUrl = "#{url}?page=userResults"
    response = getHtml(searchUrl)
    if response.status == 200
      userCollection = response.body.scan /UserMatchFrame\">([^<]*)/
      c =  userCollection.collect {|u| u[0]}
      return c
    else
      logInfoMsg("WARNING:  userDomainAux.users getHtml request did not succeed (status=#{response.status})")
    end
  end

  # Retrieves all information (except password) for userName
  def getUser(userName)
    begin
      aUrl = "#{url}?page=userAction&action=Edit&uid=#{CGI.escape(name+'\\'+userName)}"
      response = getHtml(aUrl)
      content = response.body
      user = UserClass.new
      user.name = content.scan(/User ID<[^<]*<td>([^<]*)/)[0][0]
      user.passwd = nameSansDomain(user.name)
      user.firstname = content.scan(/name="givenName" value="([^"]*)/)[0][0]
      user.lastname = content.scan(/name="sn" value="([^"]*)/)[0][0]
      user.enableTime = content.scan(/name="enableTime" value="([^"]*)/)[0][0]
      user.mail = content.scan(/name="mail" value="([^"]*)/)[0][0]
      certOk = content.scan(/value="([^"]*)" CHECKED/)[0][0]
      user.certOkWhenDisabled = (certOk=='TRUE')
      authreq = content.scan(/value="([^"]*)".{0,40}selected/m)
      if authreq != []
        user.authreq = authreq[0][0]
      else
        user.authreq = nil
      end
      user.roles = rolesForUser(user.name)
      return user
    rescue Exception => e
      msg = "Error #{e.class}, #{e.message}, while retrieving user #{userName}"
      logInfoMsg msg
      logInfoMsg e.backtrace.join("\n")
      u = UserClass.premadeUser(userName)
      u= UserClass.new(userName, userName, "EITHER", userName, userName,
                       ['Logistician', 'PolicyAdministration'])
    end
  end

  def roles
    searchUri = "#{url}?page=roleResults"
    response = getHtml(searchUri)
    if response.status == 200
      userCollection = response.body.scan /UserMatchFrame\">([^<]*)/
      return userCollection.collect {|u| u[0]}
    else
      logInfoMsg "WARNING:  didn't retrieve html in userDomainAux.roles"
    end
  end

  def createRole(roleName, descript)
    params = "page=newRole&rid=#{CGI.escape(roleName)}&description=#{CGI.escape(descript)}"
    u = "#{url}?#{params}"
    response = getHtml(u)
    unless response.status == 200
      logInfoMsg "WARNING:  Couldn't create role in userDomainAux.createRole"
    end
  end

  def deleteRole(roleName)
    params = "page=roleAction&rid=#{CGI.escape(roleName)}&action=Delete"
    u = "#{url}?#{params}"
    response = getHtml(u)
    unless response.status == 200
      logInfoMsg "WARNING:  Couldn't delete role in userDomainAux.createRole"
    end
  end

  def rolesForUser(userName)
    userName = userName.name if userName.kind_of?(UserClass)
    searchUrl= url+'?page=displayUser&uid='+CGI.escape(userName)
    response = getHtml(searchUrl)
    if response.status == 200
      roleSection = response.body.scan(/<td>Roles<\/td>(.*)<\/table>/m)
      roleSection = roleSection[0][0]  # just want the string
      roleSection = '<td></td>' + roleSection
      roles = roleSection.scan(/<td><\/td>.....\s*<td>([^<]*)/m)
      roles = roles.collect {|role| role[0]}
      roles = roles.select {|role| role != ''}
      return roles
    end
  end

  #--------- User Methods -----------
  def recreateUsers(userCollection)
    logInfoMsg "recreating users" if $VerboseDebugging
    userCollection << "BogusUser"
    users = []
    @@mutex.synchronize do
      logInfoMsg "recreating users for #{@agent.name}" if $VerboseDebugging
      caDomainName = @agent.caDomains[0].name
      userCollection.each do |u|
        logInfoMsg "in recreateUsers: #{u}" if $VerboseDebugging
        fullUserName = ''
        if u.kind_of?(UserClass)
          fullUserName = "#{caDomainName}#{u.name}"
        else
          fullUserName = "#{caDomainName}#{u}"
        end
        if !@@createdUsers.member?(fullUserName)
          users << u
          @@createdUsers << fullUserName
        end
      end
    end
    recreateUsersForce(users)
  end

  def UserClass.clearCache
    @@createdUsers = []
  end

  def recreateUsersForce(userCollection)
    userCollection.each do |user|
      logInfoMsg "  #{user}" if $VerboseDebugging
      user = UserClass.premadeUser(user) if user.kind_of?(String)
      begin
        recreateUser(user)
      rescue Exception => e
        logInfoMsg "Error while recreating user #{user}: #{e.class} #{e.message}"
        logInfoMsg e.backtrace.join("\n")
      end
    end
  end

  def recreateUser(aUser, createCert=true)
    aUser = getUser(aUser) if aUser.kind_of?(String)
    deleteUser aUser.name
    createUser aUser, createCert
  end

  def createUser(user, createCert=true)
    params = createUserParams user
    params << "page=newUser"
    params << "action=Add+User"
    response = postHtml url, params
    #      puts "  Status: #{response.status}"
    setUserRoles(user)

    # Create the certificate if needed.
    #      case user.authreq
    #      when "CERT", "BOTH", "EITHER"
    if true
      if createCert
        #puts "creating cert" if $VerboseDebugging
        CaDomains.instance.ensureExpectedEntities
        agent.caDomains[0].createUserCert user.name
      end
    end
  end

  def updateUser(user)
    params = createUserParams user
    params << "page=editUser"
    params << "action=Save"
    response = postHtml(url, params)
    if $VerboseDebugging
      logInfoMsg "updateUser  Status: #{response.status}"
      logInfoMsg "updateUser #{params}"
    end
    setUserRoles(user)
  end

  def deleteUser(userName)
    #logInfoMsg "Deleting user #{userName}"
    params = ["page=userAction", "action=Delete", "uid=#{CGI.escape(name+'\\'+userName)}"]
    response = postHtml url, params
    #      puts "  Status: #{response.status}"
  end

  def disableUser(user)
    saveAssertion "SecurityMop2.1", "Disable User: #{user}"
    user = getUser(user) if user.kind_of?(String)
    user.disable
    updateUser(user)
  end

  def enableUser(user)
    user = getUser(user) if user.kind_of?(String)
    user.enable
    updateUser(user)
  end
  
  def nameSansDomain(userName)
    userName.split(/\\/)[-1]
  end

  def createUserParams(user)
    params = []
    fullname = "#{user.firstname} #{user.lastname}"
    params << "cn=#{CGI.escape(fullname)}"
    params << "uid=#{CGI.escape(user.name)}"

    username = nameSansDomain(user.name)
    user.passwd = username if user.passwd==''
    passwd = CGI.escape(user.passwd)
    params << "password=#{passwd}"
    params << "password-repeat=#{passwd}"
    params << "enableTime=#{user.enableTime}"
    params << "certOk=#{user.certOkWhenDisabled.to_s.upcase}"
    params << "auth=#{user.authreq}"

    params << "givenName=#{user.firstname}"
    params << "sn=#{user.lastname}"
    params << "mail=#{CGI.escape(username+'@ultralog.org')}"
    params << "title=Joint Test Group"
    params << "street=2110+Washington+Blvd"
    params << "l=Arlington"
    params << "st=VA"
    params << "postalCode=22204"
    params << "telephoneNumber=703-486-4577"
    params << "homePhone="
    params << "mobile="
    params << "pager="
    params << "facsimileTelephoneNumber="
    params = params.sort
  end

  #----------  Role Methods -----------
  def setUserRoles(user)
    params = createUserRoleParams(user)
    # puts params.as_string
    getHtml("#{url}?#{params.join('&')}", 60)
  end

  def createUserRoleParams(user)
    roles = user.roles
    #if (roles.size > 1)
    params = []
    params << "page=assignRole"
    params << "action=Update+Roles"
    params << "uid=#{CGI.escape(name+'\\'+user.name)}"
    roles.each do |role|
      params << "roles=#{CGI.escape(name+'\\'+role)}"
    end
    return params
    #end
    #return nil
  end


  def do_cert_auth(userName, hostName, portNumber, urlPath)
    logInfoMsg "Doing Certificate Authentication for #{urlPath} with user=#{userName} on host #{hostName}"
    return nil if ( userName == nil || hostName == nil || urlPath == nil)
    begin
      certFile = "#{userName}_cert.pem"
      keyFile = "#{userName}_key.pem"
      #      portNumber = run.society.agents['NCA'].node.secure_cougaar_port
      logInfoMsg "python ./do_cert_auth.py '#{hostName}' '#{portNumber}' '#{certFile}' '#{keyFile}' '#{urlPath}'"
      resp = %x{python ./do_cert_auth.py '#{hostName}' '#{portNumber}' '#{certFile}' '#{keyFile}' '#{urlPath}'}
      logInfoMsg "RETCODE=|#{resp}| :Login to #{urlPath} using user=#{userName} and GoodCertificate"
      return resp
    rescue Exception => e
      logInfoMsg "Cougaar::AssessmentOperations exception"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
  end

  def do_bogus_cert_auth(userName, hostName, urlPath)
    return nil if ( userName == nil || hostName == nil || urlPath == nil )
    return do_cert_auth("bogus_"+userName, hostName, urlPath)
  end

end # UserDomain


#end # module Model
#end # module Cougaar




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
