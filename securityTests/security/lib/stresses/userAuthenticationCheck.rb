class Security1a < SecurityStressFramework
   def preConditionalNextOPlanStage
      setup
   end

   def setup
      unless @userDomain
         UserDomains.instance.ensureUserDomains
         @userDomain = run.society.agents['NCA'].userDomain
         #@userDomain = UserDomains.instance['ConusUserDomainComm']
      end
   end

   def postConditionalNextOPlanStage
      success = true

#      addRearPolicyAdmin
      sleep 5.minutes unless $WasRunning

      setup

      # -----------------------------------------------      
      puts "getting user mbarger"
      mbarger = @userDomain.getUser("mbarger")
      puts mbarger

      mbargerRoles = ['PolicyAdministrator', 'Logistician', 'UserManager', 'CAAdministrator', 'SocietyAdmin', 'LogisticsViewer', 'MonitorManager']
      mbargerRoles = mbargerRoles.collect {|r| 'ConusUserDomainComm\\'+r}

      mbargerOk = true
      mbargerOk = false if mbarger.name != 'ConusUserDomainComm\\mbarger'
      mbargerOk = false if mbarger.authreq != 'EITHER'
      mbargerOk = false if mbarger.certOkWhenDisabled != true
      mbargerOk = false if mbargerRoles-mbarger.roles != []
      if mbargerOk
        saveResult(true, "1a209", "mbarger listing is correct")
      else
        saveResult(false, "1a209", "User mbarger listing is not correct")
        success = false
      end


      # -----------------------------------------------      
      puts "recreating users"
      userSet = %w(BogusUser BadUser ALogistician CertUser CertAndPassUser DisabledLogistician DeletedLogistician FwdPolicyUser)

      unless false  #$WasRunning
        @userDomain.recreateUsers(userSet)
        @userDomain.disableUser('DisabledLogistician')
        @userDomain.deleteUser('DeletedLogistician')
      end

      puts "done recreating users"
      sleep 2.minutes unless $WasRunning

      # -----------------------------------------------
      allUsers = @userDomain.users
      allRoles = @userDomain.roles
puts "allRoles = #{allRoles.inspect}"
      expectedUsers = userSet - ["DeletedLogistician"] + ["mbarger","george","sally"]
      expectedUsers = expectedUsers.collect {|u| 'ConusUserDomainComm\\'+u}
      missingUsers = expectedUsers - allUsers
      expectedRoles = %w(PolicyAdministrator Logistician UserManager CAAdministrator SocietyAdmin LogisticsViewer MonitorManager)
      expectedRoles = expectedRoles.collect {|r| 'ConusUserDomainComm\\'+r}
      missingRoles = expectedRoles - allRoles
      useCases = "1a201,1a209,1a210,1a211"
      if missingUsers==[] and missingRoles==[]
        saveResult(true, useCases, "All users and roles accounted for")
      else
        saveResult(false, useCases, "Some users (#{missingUsers.inspect}) or some roles (#{missingRoles.inspect}) not loaded from configuration file")
        success = false
      end

      # -----------------------------------------------
      if !allUsers.member?('ConusUserDomainComm\\DeletedLogistician')
        saveResult(true, "1a203", "User successfully deleted")
      else
        saveResult(false, "1a203", "User was not successfully deleted")
        success = false
      end

      # -----------------------------------------------
      disabled = @userDomain.getUser('DisabledLogistician')
      if disabled and disabled.enableTime==''
        saveResult(true, "1a207", "User successfully disabled")
      else
        saveResult(false, "1a207", "User was not successfully disabled")
        success = false
      end

      # -----------------------------------------------
      disabled.authreq = "BOTH"
      @userDomain.updateUser(disabled)
      newdisabled = @userDomain.getUser('DisabledLogistician')
      if newdisabled.authreq == "BOTH"
        saveResult(true, "1a208", "User authreq successfully changed")
      else
        saveResult(false, "1a208", "User authreq was not successfully changed")
        success = false
      end

      # -----------------------------------------------
      origroles = @userDomain.rolesForUser(disabled)
      roleToAdd = "ConusUserDomainComm\\PolicyAdministrator"
      newroles = origroles << roleToAdd
      disabled.roles = newroles
      @userDomain.setUserRoles(disabled)
      newroles2 = @userDomain.rolesForUser(disabled)
      missingRoles = newroles - newroles2
      if missingRoles == []
        saveResult(true, "1a205", "User role successfully added")
      else
        saveResult(false, "1a205", "User role not successfully added")
        success = false
      end

      # -----------------------------------------------
      disabled.roles = newroles - [roleToAdd]
      @userDomain.setUserRoles(disabled)
      newroles3 = @userDomain.rolesForUser(disabled)
      stillThere = newroles3.member?(roleToAdd)
      if !stillThere
        saveResult(true, "1a206", "User role successfully removed")
      else
        saveResult(false, "1a206", "User role not successfully removed")
        success = false
      end

      # -----------------------------------------------
      roleToAdd = 'ConusUserDomainComm\\NewRole'
      @userDomain.createRole(roleToAdd, 'Testing of role creation')
      newroles = @userDomain.roles
      missingRoles = (allRoles+[roleToAdd]) - newroles
      if missingRoles == []
        saveResult(true, "1a202", "Role successfully created")
      else
        saveResult(false, "1a202", "Role not successfully created")
        success = false
      end

      # -----------------------------------------------
      @userDomain.deleteRole(roleToAdd)
      newroles2 = @userDomain.roles
      stillThere = newroles2.member?(roleToAdd)
      if !stillThere
        saveResult(true, "1a204", "Role successfully deleted")
      else
        saveResult(false, "1a204", "Role not successfully deleted")
        success = false
      end

      # -----------------------------------------------
      # -----------------------------------------------
      # -----------------------------------------------
      # -----------------------------------------------

#      storeIdmefs
      captureIdmefs

      ncaAgent = run.society.agents["NCA"]
      servlet = '/editOplan'
      goodUser = 'ALogistician'
      goodPassword = 'ALogistician'
      badUser = 'BadUser'
      badPassword = ''
      nonExistent = 'IAmNotAUser'
      certUser = 'CertUser'
      disabled = "DisabledLogistician"
      conusAdmin = "ConusPolicyAdmin"
      tests = [
         # auth    agent     user      password      servlet  expectedResponse
         ['Basic', ncaAgent, badUser,  badPassword,  servlet, 401, '1a6',
                   'WRONG_PASSWORD', '1a25'],
         ['Basic', ncaAgent, goodUser, badPassword,  servlet, 401, '1a1',
                   'WRONG_PASSWORD', '1a20'],
         ['Basic', ncaAgent, goodUser, goodPassword, servlet, 200, '1a101,1a109'],
         ['Basic', ncaAgent, nonExistent, nonExistent, servlet, 401, '1a7',
                   'USER_DOES_NOT_EXIST', '1a26'],
         ['Basic', ncaAgent, disabled, disabled,     servlet, 401, '1a8',
                   'DISABLED_ACCOUNT', '1a27'],
# this one works
         ['Cert',  ncaAgent, certUser, true,         servlet, 200, '1a103,1a110'],

#         ['Cert',  ncaAgent, badUser,  false,        servlet, 401],

         # this doesn't return an idmef -- it fails prior to tomcat
         ['Cert',  ncaAgent, certUser, false,        servlet, 401, '1a2'],

#         ['Basic', ncaAgent, goodUser, goodPassword, servlet, 200],

#         ['Cert',  ncaAgent, badUser,  true,         servlet, 401],

# this one hangs
#         ['Cert',  ncaAgent, certUser, true,         servlet, 200],

#         ['Cert',  ncaAgent, certUser, false,        servlet, 401],
#         ['Cert',  ncaAgent, certUser, true,         servlet, 200],

         ['Basic', ncaAgent, conusAdmin, conusAdmin,  servlet, 401, '1b1',
                   'USER_DOES_NOT_EXIST', '1b21']
         ]

      testNum = 0        
      tests.each { |test| 
         testNum += 1
         agent=test[1]
         user=test[2]
         password=test[3]
         servlet=test[4]
         useCase=test[6]
         idmefPattern=test[7]
         idmefUseCase=test[8]
         type=test[0]
         puts "Accessing #{servlet} at #{agent} with '#{user}/#{password}' - Type: #{type}"
         pattern = /#{agent.host.name}.*#{servlet}.*#{idmefPattern}/
         searchForLoginFailure(pattern) if idmefPattern
         accessSuccess = @userDomain.accessServlet(test)
         if idmefPattern
           suc = waitForLoginFailure(15)
           puts "waitsuccess = #{suc}"
           if suc
             saveResult(suc, idmefUseCase, "IDMEF was sent")
           else
             saveResult(suc, idmefUseCase, "IDMEF was not sent")
             accessSuccess = false
           end
         end
         success = false unless accessSuccess
         sleep 1.second
      }

      if success
        saveResult(true, "Experiment 1a", "Experiment passed")
      else
        saveResult(false, "Experiment 1a", "Experiment failed")
      end

      printSummary

      exit if $WasRunning
   end

   def captureIdmefs
      @found = false
      onCaptureIdmefs do |event|
         e = event.to_s
         if e =~ @idmefDescript
            @found = true
         end
      end
   end

   def searchForLoginFailure(descript)
      @found = false
      @idmefDescript = descript
   end

   def waitForLoginFailure(timeoutlen)
      1.upto(timeoutlen) do |n|
         return true if @found
         sleep 1.second
      end
      return false
   end

=begin
   def postStopSociety
      puts 'userTries:'
      puts @userTries
      puts 'idmefs:'
      puts @idmefs
   end
=end

=begin
   def addRearPolicyAdmin
      Util.modifyPolicy(ncaEnclave, '', '
Policy DamlBootPolicyNCAServletForRearPolicyAdmin = [
  A user in role RearPolicyAdministration can access a servlet named NCAServlets
]
')
   end
=end

end
