##
#  <copyright>
#  Copyright 2002 System/Technology Devlopment Corp.
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

require "socket"

module Cougaar
  module Actions
=begin
    class CreateNewCnCRun < Cougaar::Action
      RESULTANT_STATE = "CnCDbInitialized"
      def initialize(run, type, desc=nil, mode=nil, host=nil)
        super(run)
        @type = type
        if mode != nil
          @mode = mode
        else
          @mode = 'script'
        end
        @desc = desc
        if host != nil
          @host = host
        else
          @host = ::Cougaar::EnvSetup['OperatorServiceHost']
        end
        @desc = @run.name unless @desc
      end

      def perform
        case @mode
        when 'script'
          db_conf = {}
          if ::Cougaar::EnvSetup['CnCDbSetting']['Server'] != nil
            db_conf['Server'] = ::Cougaar::EnvSetup['CnCDbSetting']['Server']
          else
            db_conf['Server'] = "cnccalc-db"
          end

          port = ::Cougaar::EnvSetup['CnCDbSetting']['Port']
          db_conf['Port'] = port if port

          if ::Cougaar::EnvSetup['CnCDbSetting']['Dbname'] != nil
            db_conf['Dbname'] = ::Cougaar::EnvSetup['CnCDbSetting']['Dbname']
          else
            db_conf['Dbname'] = Socket.gethostname
          end

          if ::Cougaar::EnvSetup['CnCDbSetting']['User'] != nil
            db_conf['User'] = ::Cougaar::EnvSetup['CnCDbSetting']['User']
          else
            db_conf['User'] = "postgres"
          end

          if ::Cougaar::EnvSetup['CnCDbSetting']['Passwd'] != nil
            db_conf['Passwd'] = ::Cougaar::EnvSetup['CnCDbSetting']['Passwd']
          else
            db_conf['Passwd'] = ""
          end

          #puts "#{db_conf['Server']} #{db_conf['Port']} #{db_conf['Dbname']} #{db_conf['User']} #{db_conf['Passwd']}"

          cnc_db = ::Assessment::CnCcalcDatabase.new(db_conf)
          schema_check = cnc_db.check_schema()
          if (schema_check == false)
            if ::Cougaar::EnvSetup['CnCDbSetting']['CreateSql'] != nil
              create_sql = ::Cougaar::EnvSetup['CnCDbSetting']['CreateSql']
            else
              cip = ENV['CIP']
              create_sql = File.join(cip, 'CnCcalc','bin','CreateCnCPostgres.sql')
            end

            schema_check = cnc_db.create_tables(create_sql)
          end
          @run['cnc_id'] = Time.now.to_i
          @run['type'] = @type if @run['type'] == nil
          if ( schema_check == true)
            cnc_db.create_run(@run['cnc_id'], @type, @run.name, @desc)
            @run.info_message "CnCcalc run id for this experiment is #{@run['cnc_id']}"
          end
        when 'web'
          puts "To be implemented yet"
        end
      end
    end
    
    class CreateNewCnCBaselineRun < Cougaar::Actions::CreateNewCnCRun
      def initialize(run, desc=nil, mode=nil, host=nil)
        super(run, 'base', desc, mode, host)
      end
    end
    
    class CreateNewCnCStressRun < Cougaar::Actions::CreateNewCnCRun
      def initialize(run, desc=nil, mode=nil, host=nil)
        super(run, 'stress', desc, mode, host)
      end
    end

    class LogCnCData < Cougaar::Action
      PRIOR_STATES = ["CnCDbInitialized"]
      RESULTANT_STATE = "CnCLogging"
      def initialize(run)
        super(run)
        @cnc_class = 'com.stdc.CnCcalc.plugin.CnCcalcPlugin'
      end
      
      def perform
        doSleep = false
        @run.society.each_agent do |agent|
          if agent.has_component?{|c| c.classname == @cnc_class}
            begin
              result2, uri2 = Cougaar::Communications::HTTP.get("#{agent.uri}/cnccalc?command=start", 300)
              #puts result2 if result2
              Cougaar.logger.info "#{agent.name}: "
              Cougaar.logger.info "#{result2}" if result2
            rescue Exception => e
              Cougaar.logger.info "Exception sending start to cnccalc plugin in #{agent.name}"
              Cougaar.logger.info e.backtrace.join("\n")
            end
            if doSleep
              sleep 1
              doSleep = false
            else
              doSleep = true
            end
          end
        end
      end
    end

    class ArchiveCnCRun < Cougaar::Action
      RESULTANT_STATE = "CnCDbArchived"
      def initialize(run, db_server=nil, db_name=nil, db_user=nil, db_passwd=nil, db_port=nil) 
        super(run)
        #@run['cnc_archive_name'] = "CnCDump-#{@run['cnc_id']}.tgz"
        @run['cnc_archive_name'] = "cnc_db_dump.tgz"
        @run.archive_and_remove_file(@run['cnc_archive_name'], "CnCcalc db dump")
        @db_conf = {}
        @db_conf['Server'] = db_server
        @db_conf['Dbname'] = db_name
        @db_conf['User'] = db_user
        @db_conf['Passwd'] = db_passwd if db_passwd != nil
        @db_conf['Port'] = db_port if db_port != nil
      end

      def perform
        @db_conf['Server'] = "cnccalc-db" if @db_conf['Server'] == nil
        @db_conf['Dbname'] = Socket.gethostname if @db_conf['Dbname'] == nil
        @db_conf['User'] = "postgres" if @db_conf['User'] == nil

        cnc_db = ::Assessment::CnCcalcDatabase.new(@db_conf)
        cnc_db.archive_db(@run['cnc_archive_name'])
      end
    end
    
    class ResetCnCDb < Cougaar::Action
      RESULTANT_STATE = "CnCDbReset"
      def initialize(run, db_server=nil, db_name=nil, db_user=nil, db_passwd=nil, db_port=nil) 
        super(run)
        @db_conf = {}
        @db_conf['Server'] = db_server
        @db_conf['Dbname'] = db_name
        @db_conf['User'] = db_user
        @db_conf['Passwd'] = db_passwd if db_passwd != nil
        @db_conf['Port'] = db_port if db_port != nil
      end

      def perform
        @db_conf['Server'] = "cnccalc-db" if @db_conf['Server'] == nil
        @db_conf['Dbname'] = Socket.gethostname if @db_conf['Dbname'] == nil
        @db_conf['User'] = "postgres" if @db_conf['User'] == nil

        cnc_db = ::Assessment::CnCcalcDatabase.new(@db_conf)
        cnc_db.reset_db

        if ::Cougaar::EnvSetup['CnCDbSetting']['CreateSql'] != nil
          create_sql = ::Cougaar::EnvSetup['CnCDbSetting']['CreateSql']
        else
          cip = ENV['CIP']
          create_sql = File.join(cip, 'CnCcalc','bin','CreateCnCPostgres.sql')
        end

        cnc_db.create_tables(create_sql)
      end
    end
    
    class StartCnCcalcService < Cougaar::Action
      PRIOR_STATES = ["CommunicationsRunning"]
      DOCUMENTATION = Cougaar.document {
        @description = "Starts the CnCcalculator service on the operator machine"
        @example = "do_action 'StartCnCcalcService'"
      }

      def perform
        op_host = @run.society.get_service_host('operator')
        msg = @run.comms.new_message(op_host).set_body("command[rexec_user]$CIP/CnCcalc/server/start_cnc_server.csh").request(30)
        #puts "#{msg}"
      end
    end

    class StopCnCcalcService < Cougaar::Action
      PRIOR_STATES = ["CommunicationsRunning"]
      DOCUMENTATION = Cougaar.document {
        @description = "Stops the CnCcalculator service on the operator machine"
        @example = "do_action 'StopCnCcalcService'"
      }

      def perform
        op_host = @run.society.get_service_host('operator')
        msg = @run.comms.new_message(op_host).set_body("command[rexec_user]$CIP/CnCcalc/server/stop_cnc_server.csh").request(30)
        puts "#{msg}"
      end
    end
=end

    class StartCnCXmlSave < Cougaar::Action
      PRIOR_STATES = ["SocietyRunning"]
      RESULTANT_STATE = "CnCLogging"
      def initialize(run, type='stress', desc=nil, exp_id=nil)
        super(run)
        @run['type'] = type
        @run['cnc_id'] = Time.now.to_i
        @run['cnc_status'] = []
        if(exp_id == nil)
          @exp_id = @run.name
        else
          @exp_id = exp_id
        end
        if(desc == nil)
          @desc = @exp_id
        else
          @desc = desc
        end
        @cnc_class = 'com.stdc.CnCcalc.plugin.CnCcalcPlugin'
      end
      
      def perform
        @run.society.each_agent do |agent|
          params = "command=start&run_id=#{@run['cnc_id']}&type=#{@run['type']}&exp_id=#{@exp_id}&desc=#{@desc}"
          if agent.has_component?{|c| c.classname == @cnc_class}
            begin
              #result2, uri2 = Cougaar::Communications::HTTP.get("#{agent.uri}/cnccalc?"+"#{params}")
              result2, uri2 = Cougaar::Communications::HTTP.post("#{agent.uri}/cnccalc", params)
              scan_result = result2.scan(/Received Command to start log/)
              if( scan_result != nil && !scan_result.empty? )
                @run['cnc_status'] << agent.name
                #Cougaar.logger.info "#{agent.name}: "
                #Cougaar.logger.info "#{result2}" if result2
              end
            rescue Exception => e
              Cougaar.logger.info "Exception sending start to cnccalc plugin in #{agent.name}"
              Cougaar.logger.info e.backtrace.join("\n")
            end
          end
        end
      end
    end
  end
  
  module States
#    class CnCDbInitialized < Cougaar::NOOPState
#    end
    
    class CnCLogging < Cougaar::NOOPState
    end
    
#    class CnCDbArchived < Cougaar::NOOPState
#    end
    
#    class CnCDbReset < Cougaar::NOOPState
#    end
    
=begin
    class CnCLoggingComplete < Cougaar::State
      DEFAULT_TIMEOUT = 90.minutes
      PRIOR_STATES = ["CnCLogging"]
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
      end
      
      def process
        loop = true
        while loop
          event = @run.get_next_event
          if event.event_type=="STATUS" && event.data.include?("state=LOGGING_COMPLETE")
            loop = false
          end
        end
      end
      
      def unhandled_timeout
        @run.do_action "StopSociety" 
        @run.do_action "ArchiveCnCRun"
        @run.do_action "StopCommunications"
      end
    end
=end

    class CnCXmlSaveEnd < Cougaar::State
      DEFAULT_TIMEOUT = 15.minutes
      PRIOR_STATES = ["CnCLogging"]
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
      end
      
      def process
        Cougaar.logger.error "No Agent received start command" if @run['cnc_status'].empty?
        while !@run['cnc_status'].empty?
          event = @run.get_next_event
          if event.event_type=="STATUS" && event.data.include?("state=END_LOGGING")
            if( @run['cnc_status'].delete(event.cluster_identifier) == nil)
              Cougaar.logger.info "Could not find #{event.cluster_identifier} in cnc started agents"
            else
              Cougaar.logger.info "#{event.cluster_identifier}: Received #{event.data}"
            end
          end
        end
      end
    end
  end
end

=begin
require 'postgres'

module Assessment

  class CnCcalcDatabase

    def initialize(db_conf)
      @db_host = db_conf['Server']
      @db_port = db_conf['Port']
      @db_name = db_conf['Dbname']
      @db_user = db_conf['User']
      @db_passwd = db_conf['Passwd']
    end

    def check_schema ()
      schema_check = nil
      begin
        db_conn = PGconn.connect( @db_host, @db_port, nil, nil, @db_name, @db_user, @db_passwd )
    
        listbuf  = "SELECT usename, relname, relkind, relhasrules"
        listbuf += "  FROM pg_class, pg_user "
        listbuf += "WHERE usesysid = relowner "
        listbuf += "and ( relkind = 'r') and relname !~ '^pg_' "
        listbuf += "  ORDER BY relname "
        res = db_conn.exec(listbuf)
        if (res == nil || res.status != PGresult::TUPLES_OK)
          raise PGError,"Error in fetching table list\n"
        end
        nColumns = res.num_tuples
        #puts "No. of tables #{nColumns}"

        if nColumns > 0
          for i in 0..nColumns-1
            relation = res.getvalue(i, 1)
            if ( relation == "runs" )
              schema_check = TRUE
              break;
            end
          end
        else
          schema_check = FALSE
        end
        res.clear()
        db_conn.close
        return schema_check
      rescue PGError
        printf(STDERR, db_conn.error) if ( db_conn != nil )
        raise
      end
    end

    def create_tables(sql_file)
      done = FALSE
      queryWaiting = nil
      fd = File.open(sql_file, "r")
      while !done
        line = fd.gets
        if line == nil
          #printf("EOF\n")
          done = TRUE
        else
          begin_comment = line.index("--")
          if begin_comment
            line = line[0, begin_comment]
          end
      
          ### erase unnecessary characters ###
          #line.gsub!(/[\s]+\z/, "")
          #if line.length == 0
          #  next
          #end
          #puts "#{line}"
      
          if queryWaiting 
            queryWaiting += " " + line 
          else
            queryWaiting =  line
          end
        end
      end
      #puts "#{queryWaiting}"
      fd.close()
    
      ret_value = FALSE
      begin
        db_conn = PGconn.connect( @db_host, @db_port, nil, nil, @db_name, @db_user, @db_passwd )
    
        res = db_conn.exec(queryWaiting)
        if ( res != nil )
          if (res.status == PGresult::COMMAND_OK ||
              res.status == PGresult::TUPLES_OK )
            res.clear
            ret_value = TRUE
          end
        end
        db_conn.close
      rescue PGError
        printf(STDERR, db_conn.error) if ( db_conn != nil )
        raise
      end
      return ret_value
    end

    def create_run(new_id=nil, type='base', exp_id='Planning', desc='Planning Baseline')
      begin
        conn = PGconn.connect( @db_host, @db_port, nil, nil, @db_name, @db_user, @db_passwd )
    
        res = conn.exec("BEGIN")
        res.clear
        res = conn.exec("DECLARE myportal CURSOR FOR select * from runs order by id")
        res.clear
    
        res = conn.exec("FETCH ALL in myportal")
        if (res.status != PGresult::TUPLES_OK)
          raise PGError,"FETCH ALL command didn't return tuples properly\n"
        end
    
        update_queries = []
        fld_id = res.fieldnum("id")
        fld_status = res.fieldnum("status")
        for i in 0...res.num_tuples
          id = res.getvalue(i, fld_id).to_i
          status = res.getvalue(i, fld_status).to_i
          if ( status == 0)
            status = 55
            update_queries << 
              "UPDATE runs SET status = #{status} where id=#{id};"
          end
        end
    
        res = conn.exec("CLOSE myportal")
        res = conn.exec("END")
        res.clear
        update_queries.each do |query|
          #puts "#{query}"
          res = conn.exec(query)
          if (res.status() != PGresult::COMMAND_OK )
            puts "Error in running query #{query}"
          end
          res.clear
        end
        create_buf = "INSERT INTO runs (id, status, type, experimentid, description)"
        create_buf += " VALUES (#{new_id}, 0, \'#{type}\', \'#{exp_id}\', \'#{desc}\');"
        res = conn.exec( create_buf )
        if (res.status() != PGresult::COMMAND_OK )
          puts "Error in inserting new run entry"
          raise PGError,"Error in inserting new run entry\n"
        end
        res.clear
        conn.close
      rescue PGError
        printf(STDERR, conn.error) if ( conn != nil )
        raise
      end
    end

    def archive_db(file_name)
      cmd_str = "pg_dump -Ft -U#{@db_user} "
      cmd_str += "-h#{@db_host} " if @db_host
      cmd_str += "-p#{@db_port} " if @db_port
      cmd_str += "#{@db_name} | gzip -f > #{file_name}"
      #puts "#{cmd_str}"
      `#{cmd_str}`
      exe_status = $?
      return false if ( exe_status != 0 )
      return true
    end

    def reset_db
      ret_status = true
      begin
        db_conn = PGconn.connect( @db_host, @db_port, nil, nil, @db_name, @db_user, @db_passwd )
    
        listbuf  = "SELECT usename, relname, relkind, relhasrules"
        listbuf += "  FROM pg_class, pg_user "
        listbuf += "WHERE usesysid = relowner "
        listbuf += "and ( relkind = 'r') and relname !~ '^pg_' "
        listbuf += "  ORDER BY relname "
        res = db_conn.exec(listbuf)
        if (res == nil || res.status != PGresult::TUPLES_OK)
          raise PGError,"Error in fetching table list\n"
        end
        nColumns = res.num_tuples
        #puts "No. of tables #{nColumns}"

        if nColumns > 0
          for i in 0..nColumns-1
            relation = res.getvalue(i, 1)
            sqlbuf = "DROP TABLE \"#{relation}\";"
            #puts "#{sqlbuf}"
            res1 = db_conn.exec(sqlbuf)
            if (res1 == nil || res1.status != PGresult::COMMAND_OK)
              ret_status = false
            end
            res1.clear()
          end
        #else
        #  puts "No tables found in database #{@db_name} on #{@db_host}"
        end
        res.clear()
        db_conn.close
        return ret_status
      rescue PGError
        printf(STDERR, db_conn.error) if ( db_conn != nil )
        raise
      end
    end

  end
end
=end

if $0==__FILE__
db_conf = {}
db_conf['Server'] = 'sb042'
db_conf['Dbname'] = 'drop_test'
db_conf['User']   = 'postgres'

cnc_db = Assessment::CnCcalcDatabase.new(db_conf)
cnc_db.reset_db
end
