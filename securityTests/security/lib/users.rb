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

require 'security/lib/experimentFramework'
require 'user_admin'
require 'security/lib/web'

$AccessServletDomain = "UserDomain1"

=begin
      if authentication == 'Basic'
         result = AssessmentOperations.do_basic_auth(user, password, agent.node.host.host_name, agent, servlet, run.society.cougaar_port, 90)
      elsif password == true then
         result = AssessmentOperations.do_cert_auth(user, agent.host, servlet)
      else
         result = AssessmentOperations.do_bogus_cert_auth(user, agent.host, servlet)
      end
=end

SecurityUser = Struct.new("SecurityUser", :uid, :passwd, :authreq, :firstname, :lastname, :roles)

SECURITY_USERS = 
  [ 
    SecurityUser.new("PolAdmin", "PolAdmin", "EITHER", "PolicyAdministrator", "SecureSociety", ["PolicyAdministrator"]),
    SecurityUser.new("UsrMngr", "UsrMngr", "EITHER", "UserManager", "SecureSociety", ["UserManager"]),
    SecurityUser.new("ALogistician", "ALogistician", "EITHER", "Logistician", "SecureSociety", ["Logistician"]),
    SecurityUser.new("LogViewer", "LogViewer", "EITHER", "LogisticsViewer", "SecureSociety",  ["LogisticsViewer"]),
    SecurityUser.new("Mover", "Mover", "EITHER", "Mover", "SecureSociety", ["SocietyAdmin"]),
    SecurityUser.new("CertAndPassUser", "CertAndPassUser", "EITHER", "CertAndPassUser", "SecureSociety",  ["Logistician"]),
    SecurityUser.new("CertUser", "CertUser", "CERT", "CertUser", "SecureSociety", ["Logistician"]),
    SecurityUser.new("Nobody", "Nobody", "EITHER", "Nobody", "SecureSociety",  [])
  ]

class UserAdmin
   attr_accessor :agent, :port, :host, :url
   
   def initialize(run, agent="UserAdminAgent1", port=nil)
      @run = run
      @agent = agent
      @agent = run.society.agents[agent] if agent.class == String
      @port = port
      @port = run.society.cougaar_port unless port
      
      @host = agent.host
      @url = "#{@agent.uri}/useradmin"
   end
   
   def recreateUsers(users=SECURITY_USERS)
      deleteUsers(users)
      createUsers(users)
   end
   
   def deleteUsers(users)
      users.each do |user|
         deleteUser user
         deleteUserCertFiles user
      end
   end
   def createUsers(users)
      users.each do |user|
         createUser user
         assignUserRoles user
         createUserCertFiles user
      end
   end
   
   def deleteUser(user)
      logInfoMsg "Deleting user #{user.uid}"
      params = ["page=userAction", "action=Delete", "uid=#{user.uid}"]
      postHtml(@url, params)
   end
   def deleteUserCertFiles(securityUser)
      user = securityUser.uid
      ["#{user}_key.pem"  "bogus_#{user}_key.pem"  "#{user}_cert.pem"  "bogus_#{user}_cert.pem"].each do |file|
         begin
            File.delete(file)
         rescue
            logInfoMsg $!
         end
      end
   end
   
   def createUser(user)
      params = createUserParams user
      result = postHtml @url, params
   end
   def createUserCertFiles(user)
      params = createOpenSSLParams user
   end
   def assignUserRoles(user)
      params = createUserRoleParams user
      result = getHtml("#{@url}?#{params.join('&')}, 60) if params
   end
   
   
   
   
   :private

   def  createUserParams(user)
      params = []
      params << "page=newUser"
      params << "action=Add+User"
      params << "cn=#{firstname}+#{user.lastname}"
      params << "uid=#{user.uid}"

      params << "password=#{user.passwd}"
      params << "password-repeat=#{user.passwd}"
      params << "enableTime=19700101000000Z"
      params << "certOk=FALSE"
      params << "auth=#{user.authreq}"

      params << "givenName=#{user.firstname}"
      params << "sn=#{user.lastname}"
      params << "mail=#{user.uid}@ultralog.org"
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
   end

   def  createUserRoleParams(user)
      roles = user.roles
      if (role.size > 1)
         params = []
         params << "page=assignRole"
         params << "action=Update+Roles"
         params << "uid=#{user.uid}"
         roles.each do |role|
            params << "roles=#{role}"
         end
         return params
      end
      return nil
   end
   
   def createOpenSSLParams(user)
   
   end
end



# Attempts accessing a servlet
def accessServlet(test)
   basicAuthPort = run.society.cougaar_port
   timeout = 90
   if test[0].class == Integer then
      count = test[0]
      test = test[1..-1]
   else
      count = 1
   end
   authentication = test[0]
   agent = test[1]
#   user = @@accessServletDomain+'\\'+test[2]
   user = test[2]
   password = test[3]
   servlet = test[4]
   expectedResult = test[5]
   
   count.times do |time|
      if authentication == 'Basic'
         set_auth(@@accessServletDomain+"\\"+user, password)
         url = "http://#{agent.node.host.name}:#{basicAuthPort}/$#{agent.name}#{servlet}"
         puts ['basic_auth',url,user,password].as_string
         result = getHtml(url)
#         result = do_basic_auth(user, password, agent.node.host.host_name, agent, servlet, run.society.cougaar_port, 90)
      elsif password == true then
         result = do_cert_auth(user, agent.host, servlet)
      else
         result = do_bogus_cert_auth(user, agent.host, servlet)
      end
      code = Integer(result.code)
      if code == expectedResult then
          success = 'Success'
      else
          success = 'Failed'
      end
      if code == 200 then
          allowed = 'allowed'
      else
          allowed = 'denied'
      end
      msg = "#{success}: Authentication #{allowed} with #{user}, #{password} to servlet #{servlet} (RETCODE=#{code})"
      summary msg
      addUserTry Time.now, msg, code
      sleep(1.seconds) unless time>=count
   end
end




class SecurityStressFramework
   SecurityUser = Struct.new("SecurityUser", :uid, :passwd, :authreq, :firstname, :lastname, :roles)
  
   # a basic set of users, each user should be given the
   # password that is the same as the user name
   # Note the CertAndPassUser is getting a password and a Certificate
   # the user record indicates how the user is to be authenticated
   # via password or certificate.  We have to make sure if the user
   # is supposed to be authenticated only with a certificate, the
   # password doesn't work.
   USERS = [ 
      SecurityUser.new("PolAdmin", "PolAdmin", "EITHER", "PolicyAdministrator", "SecureSociety", ["PolicyAdministrator"]),
      SecurityUser.new("UsrMngr", "UsrMngr", "EITHER", "UserManager", "SecureSociety", ["UserManager"]),
      SecurityUser.new("ALogistician", "ALogistician", "EITHER", "Logistician", "SecureSociety", ["Logistician"]),
      SecurityUser.new("LogViewer", "LogViewer", "EITHER", "LogisticsViewer", "SecureSociety", ["LogisticsViewer"]),
      SecurityUser.new("Mover", "Mover", "EITHER", "Mover", "SecureSociety", ["SocietyAdmin"]),
      SecurityUser.new("CertAndPassUser", "CertAndPassUser", "EITHER", "CertAndPassUser", "SecureSociety", ["UserManager"]),
      SecurityUser.new("CertUser", "CertUser", "CERT", "CertUser", "SecureSociety", ["Logistician"]),
      SecurityUser.new("Nobody", "Nobody", "EITHER", "Nobody", "SecureSociety", []),
   ]

   # These are the roles that are needed to run the tests
   # these roles are created already
   ROLES = [ "PolicyAdministrator",  "UserManager",  "Logistician", "LogisticsViewer", "SocietyAdmin"]         

   def recreateUsers(users)
      logInfoMsg "Cleanup previously created users and certificates"
      delete_security_users
      for user in users
         ["bogus_", ""].each do |prefix|
            ["_key.pem", "_cert.pem"].each do |suffix|
	       begin
                  File.delete("#{prefix}#{user}#{suffix}")
               rescue
                  logInfoMsg $!
               end
            end
         end
      end
    
      logInfoMsg "Creating new users for experiment at #{run.elapsed_time}."
      create_security_users
      for user in users
         logInfoMsg "Creating a good certificate for #{user}"
         create_cert(user)
         logInfoMsg "Creating a bad certificate for #{user}"
         create_bogus_cert(user)
      end
   end # recreateUsers

   def delete_security_users
      useradmin_agent = run.society.agents["UserAdminAgent1"]
      user_admin = UserAdmin.for_cougaar_agent(useradmin_agent, run.society.cougaar_port)
      for user in USERS
         logInfoMsg "Deleting user #{user.uid}"
         user_admin.delete_user(user.uid)
      end
   end
  
   def create_security_users
      useradmin_agent = run.society.agents["UserAdminAgent1"]
      user_admin = UserAdmin.for_cougaar_agent(useradmin_agent, run.society.cougaar_port)
      for user in USERS
         logInfoMsg "Creating user #{user.uid}"
         user_admin.create_new_user(user.uid, user.passwd, user.authreq, user.firstname, user.lastname)
         logInfoMsg "Assigning roles #{user.roles.join(',')} to user #{user.uid}"
         user_admin.assign_roles_to_user(user.uid, user.roles)
      end
   end

   # Creates the parameter file used as input to openssl
   #    which will generate a certificate request
   def createParamFile(user)
     
     url = @@ca_signer
     # find the dnname 'CN=Enclave1_CA, OU=...'
     result = getHtml(url).body
     dnname = result.scan(/option value=\"(.*)\">/)[0][0]
     puts dnname.as_string
     
     #CN=Enclave1_CA, OU=Enclave1, O=DLA, L=San Francisco, ST=CA, C=US, T=ca
     orgUnitName = dnname.scan(/CN=(.*), OU=/)[0][0]
     orgName = dnname.scan(/, OU=(.*), O=/)[0][0]+"CA"
     city = dnname.scan(/, L=(.*), ST=/)[0][0]
     state = dnname.scan(/, ST=(.*), C=/)[0][0]
     country = dnname.scan(/, C=(.*), T=/)[0][0]
     
     #Generate a certificate request using openssl
     paramFile = File.new("params", "w")
     # country, state, locality, orgName, orgUnitName, common name, email addr
     #      parameters = "US\nVA\nArlington\nCougaar\nUltralog\n#{user}\n\n\n\n"
     parameters = "#{country}\n#{state}\n#{city}\n#{orgName}\n#{orgUnitName}\n#{user}\n\n\n\n"
     paramFile.puts parameters
     paramFile.close
     dnname
   end

   def create_cert(user, prefix='', extraParams='')
     url = @@ca_signer
     puts "create_cert for user #{user} url is #{url}"
     puts "\n"
     dnname = createParamFile(user)
     cert = %x{openssl req -nodes -new -keyout "#{user}"_key.pem -days 365 < params}
     puts
     puts "cert = #{cert}"
     File.delete("params")
     
     #Get the certificate signed
     params = []
     params << "dnname=#{CGI.escape(dnname)}"
     params << "pkcs=pkcs10"
     params << "pkcsdata=#{CGI.escape(cert)}"
     params << "replyformat=html"
     puts "params = #{(params.collect {|p| CGI.unescape(p)}).join("&")}"
     puts "getting signed_cert from url=#{url} ..."

     signed_cert = postHtml(url, params).body
     puts "signed_cert ="
     puts signed_cert
     signed_cert = CGI.unescape(signed_cert)
     array = signed_cert.split('<br>')
     array[0] = array[0].split[1]
     signed_cert = array[0..-2].join("\n")
     puts signed_cert
      #signed_cert = CGI.unescape(Cougaar::Util.do_http_post(url, params.join("&")))
     cert_file = File.new("#{user}_cert.pem", "w")
     cert_file.puts("#{signed_cert}")
     cert_file.close
   end

   def create_bogus_cert(user)
      createParamFile(user)

      #Generate a certificate request using openssl
      %x{openssl req -nodes -new -keyout "bogus_#{user}"_key.pem -x509 -out "bogus_#{user}_cert.pem" -days 365 < params}
      File.delete("params")
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

end
