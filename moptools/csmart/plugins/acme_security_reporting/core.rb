
CIP=ENV["CIP"]

$:.unshift File.join(CIP, 'csmart', 'lib')
require 'security/actions/parseResults'

module ACME
  module Plugins
    class SecurityCore
      extend FreeBASE::StandardPlugin
      
      def self.start(plugin)
        self.new(plugin)
        plugin.transition(FreeBASE::RUNNING)
      end
      
      attr_reader :plugin
      
      def initialize(plugin)
        @plugin = plugin
        @reporting = @plugin['/acme/reporting']
        load_template_engine
        @reporting.manager.add_listener(&method(:process_archive))
      end
      
      def load_template_engine
        @ikko = Ikko::FragmentManager.new
        @ikko.base_path = File.join(@plugin.plugin_configuration.base_path, "templates")
      end

      def process_archive(archive)
        puts "Processing an archive #{archive.base_name}"
        begin
          report_security_tests(archive)
          puts "Security log"
        rescue
          puts $!
          puts $!.backtrace
          archive.add_report("Exception", @plugin.plugin_configuration.name) do |report|
            report.open_file("Exception.html", "text/html", "Exception") do |out|
              out.puts "<html>"
              out.puts "<title>Exception</title>"
              out.puts "#{$!} <BR>"
              out.puts $!.backtrace.collect{|x| x.gsub(/&/, "&amp;").gsub(/</, "&lt;").gsub(/>/,"&gt;")}.join("<BR>")
              out.puts "</html>"
            end
            report.failure
          end
        end
      end
      
      def report_security_tests(archive)
        puts "Entering report_security_tests with archive #{archive}"
        security_results_file, style_sheets_file = get_archive_files(archive)
        puts "results file name = #{security_results_file}"
        puts "style sheet file name = #{style_sheets_file}"
        archive.add_report("Security", @plugin.plugin_configuration.name) do |report|
          puts "entering archive add report"
          if security_results_file then 
            puts("opened report #{report} and writing lines")
            success = true
            report.open_file("security_test_results.xml",
                             "text/xml",  
                             "Security Test Results") do |file|
              found_something = false
              File.readlines(security_results_file).each do |line|
                if !found_something then
                  found_something = true
                  puts "Found a line: #{line}"
                end
                file.puts(line)
                if success && line.index("<success>false</success>") then
                  success = false
                end
              end
            end
            puts("writing the xsl file")
            if style_sheets_file then
              report.open_file("results.xsl",
                               "text/xml",  
                               "Style Sheet") do |file|
                found_something = false
                File.readlines(style_sheets_file).each do |line|
                  if !found_something then
                    found_something = true
                    puts "Found a line: #{line}"
                  end
                  file.puts(line)
                end
              end
            end
            puts("finished writing lines - report is almost done")
            if success then
              report.success()
            else 
              report.failure()
            end
          else
            puts("No security results")
            report.open_file("NoSecurityResults.html", 
                             "text/html", 
                             "No Results") do |file|
              file.puts("<HTML>")
              file.puts("<HEAD><TITLE>No security results</TITLE></HEAD>")
              file.puts("<BODY>")
              file.puts("security_test_final_results.xml file missing")
              file.puts("</BODY>")
            end
            report.failure()
          end
        end
        puts "report completed"
      end

      def get_archive_files(archive)
        security_results_file = nil
        style_sheet_file = nil
        archive.files_with_name(/security_test_final_results\.xml/).each do |f|
          security_results_file = f.name          
        end
        if !security_results_file then
          puts "no security results file case..."
          intermediate_file=nil
          archive.files_with_name(/security_test_results\.xml/).each do |f|
            intermediate_file = f.name          
          end
          if intermediate_file then
            puts "Intermediate file = #{intermediate_file}"
            security_results_file = File.join(File.dirname(intermediate_file),
                                              "security_test_final_results.xml")
            style_sheet_file = File.join(File.dirname(intermediate_file),
                                         "results.xsl")
            puts "security results is here: #{security_results_file}"
            rp = ResultParser.new(intermediate_file, security_results_file)
            rp.parseResults()
            puts "parsed"
          end
        else 
          archive.files_with_name(/results\.xsl/).each do |f|
            style_sheet_file = f.name
          end
        end
        return [security_results_file, style_sheet_file]
      end

    end
  end
end

