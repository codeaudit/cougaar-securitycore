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

require 'cgi'
require 'uri'
require 'net/http'
require 'net/https'
require 'timeout'

#$WebVerboseDebugging = false unless $WebVerboseDebugging

def getHtml(url, timeout=1800, relocationRetries=7, retry401=true)
  SRIWeb.instance.getHtml url, timeout, relocationRetries, retry401
end

def postHtml(url, params=[], timeout=1800, header={"content_type"=>"application/x-www-form-urlencoded"})
  SRIWeb.instance.postHtml url, params, timeout
end

def set_auth(username, password)
  SRIWeb.instance.set_auth(username, password)
  logWarningMsg ["It is better to instantiate a Web object and perform set_auth on it",
      "because it is expected that the singleton object can access global information.",
      "   web = SRIWeb.new",
      "   web.set_auth('#{username}', '#{password}')"].join("\n")
end

def putHtml(uri, data, format=:as_string)
  SRIWeb.instance.putHtml(uri, data, format)
end

def checkTomcatServers(hosts, port)
  SRIWeb.instance.checkTomcatServers(hosts, port)
end

def getHtmlSsl(url, keyFile, certFile, timeout=300, relocationRetries=5, retry401=true)
  return SRIWeb.instance.getHtmlSsl(url, keyFile, certFile, timeout, relocationRetries,retry401)
end



class SRIWeb
  attr_accessor :username, :password

  def self.instance
    @@singleton = SRIWeb.new unless defined? @@singleton and @@singleton
    @@singleton
  end

  def initialize
    set_auth('mbarger', 'mbarger')
  end
  
  def set_auth(username, password)
    #Net::HTTP.version_1_2  #this should be the default
    @username = username
    @password = password
  end

  # Note: the final url (if there are redirections) may be found in response['url'].
  def getHtml(url, timeout=300, relocationRetries=7, retry401=true)
    if relocationRetries < 0
      raise "Too many web redirections: '#{url}'"
    end
    response = getHtmlAux(url, timeout)
    if response.status == 302
      newurl = response['location']
      if newurl =~ /https/
        msg = "Redirection to an https addres not allowed (#{newurl})"
        puts msg if $WebVerboseDebugging
        response = HtmlResponse.new(491, msg)
        return response
      else
        puts "Redirection from #{url} to #{newurl}" if $WebVerboseDebugging
      end
      return getHtml(newurl,timeout,relocationRetries-1,retry401)
    end
    if response.status == 401 and retry401
      puts "unauthorized access attempt, will try again (#{url}) ..." if $WebVerboseDebugging
      sleep 10.seconds
      return getHtml(url, timeout, relocationRetries-1, retry401)
    end
    return response
  end
  
  def getHtmlAux(url, timeout=300)
#puts "#{url}, #{@username}, #{@password}"
    uri = URI.parse(url)
    conn = Net::HTTP.new(uri.host, uri.port)
    conn.read_timeout = timeout
    path = uri.path
    path += "?"+uri.query if uri.query
#puts "host: #{uri.host}, #{uri.port}, #{path}"
    request = Net::HTTP::Get.new(path)
    request.basic_auth(@username, @password)
    begin
      response = conn.request(request)
if response.code=="400"
  puts "aux body: #{response.body}"
  response.each_header {|k,v| puts "  #{k} = #{v}"}
end
    rescue Exception => e
puts "WARNING:  exception in [web.rb]getHtml" if $WebVerboseDebugging
puts "<#{e.message.inspect}>" if $WebVerboseDebugging
      errnum = 499
      case e.message
      when /socket read timeout/i
        errnum = 492   # timed out
      when /Name or service not known/i
        errnum = 493   # dns lookup didn't work
      when /Connection refused/i
        errnum = 494   # web server not running on machine
      when /SSL_CTX_use_PrivateKey/i
        errnum = 497   # key values mismatch
      when /alert certificate unknown/i
        errnum = 498   # certificate has probably been revoked
      else
        logInfoMsg "Unknown web exception: #{e.message}"
      end
      response = HtmlResponse.new(errnum, "ERROR: #{e.message}")
    end
#puts response.class
#puts response.status
    response['url'] = url
    return response
  end

  def postHtml(url, params=[], timeout=5.minutes, header={"content-type"=>"application/x-www-form-urlencoded"}, relocationRetries=7)
    if relocationRetries < 0
      raise "Too many web redirections: #{relocationRetries} - '#{url}'"
    end
    response = postHtmlAux(url, params, timeout, header)
    if response.status == 302
      puts "being redirected from #{url} to #{response['location']} with parameters #{params.inspect}" if $WebVerboseDebugging
      header['Cookie'] = response['set-cookie'] if response['set-cookie']
      location = response['location']
      return postHtml(location, params, timeout, header, relocationRetries-1)
    end
    if response.status == 401
      logInfoMsg "Unauthorized access attempt, will try again (#{url}) ..."
      sleep 30.seconds
      return postHtml(url, params, timeout, header, relocationRetries-1)
    end
#puts "status=#{response.code}"
    return response
  end

  def postHtmlAux(url, params=[], timeout=5.minutes, header={"content-type"=>"application/x-www-form-urlencoded"})
    uri = URI.parse(url)
    conn = Net::HTTP.new(uri.host, uri.port)
    conn.read_timeout = timeout
    path = uri.path
    path += "?"+uri.query if uri.query
    params = params.join("&") unless params.kind_of?(String)
    if $WebVerboseDebugging and false
      puts
      puts '*'*50
      puts "host=#{uri.host}:#{uri.port}, path=#{path}"
      puts "params = #{params.as_string}"
      puts '*'*50
      puts "header = #{header.as_string}"
      puts '*'*50
    end
    header = {"content-type"=>header} if header.kind_of?(String)
#puts "path: #{path}, username: #{@username}, passwd: #{@password}, params: #{params}"
    request = Net::HTTP::Post.new(path, header)
    request.basic_auth(@username, @password)
    response = conn.request(request, params)
    if $WebVerboseDebugging and false
      puts response.code
      response.each {|key, value| puts "#{key} = #{value}"}
      puts '*'*50
    end
    response['url'] = url
    return response
  end

  def getHtmlSsl(url, keyFile, certFile, timeout=300, relocationRetries=5, retry401=true)
    if relocationRetries < 0
      raise "Too many web redirections: '#{url}'"
    end
    uri = URI.parse(url)
    conn = Net::HTTP.new(uri.host, uri.port)
    conn.read_timeout = timeout
    conn.use_ssl = true
    conn.key = OpenSSL::PKey::RSA.new(File.readlines("pems/#{keyFile}").join)
    conn.cert = OpenSSL::X509::Certificate.new(File.readlines("pems/#{certFile}").join) if certFile
    conn.read_timeout = timeout
    path = uri.path
    path += "?"+uri.query if uri.query
    request = Net::HTTP::Get.new(path)
    # note: when using certs, we don't want to allow the authentication to drop back
    #       to basic authentication, so don't use this line
#    request.basic_auth('baduser', 'badpassword')
#    request.basic_auth(@username, @password)

    response = nil
    begin
      Timeout::timeout(timeout) do

        h = conn.start
        response = h.request(request)
      end
    rescue Exception => e
puts "WARNING:  web.rb.exception" if $WebVerboseDebugging
puts "<#{e.message.inspect}>" if $WebVerboseDebugging
      errnum = 499
      case e.message
      when /socket read timeout/i
        errnum = 492   # timed out
      when /Name or service not known/i
        errnum = 493   # dns lookup didn't work
      when /Connection refused/i
        errnum = 494   # web server not running on machine
      when /SSL_CTX_use_PrivateKey/i
        errnum = 497
      when /alert certificate unknown/i
        errnum = 498
      else
        logInfoMsg "Unknown web exception: #{e.message}"
      end
      response = HtmlResponse.new(errnum, "ERROR: #{e.message}")
    end

=begin
    begin
#      response = conn.get(path)
      response = conn.request(request)
puts 'got it'
    rescue Exception => e
puts 'didnt get it'
      response = HtmlResponse.new(499, "ERROR: #{e.message}")
    end
=end
    response['url'] = url
    if response.status == 302
      return getHtmlSsl(response['location'],keyFile,certFile,timeout,relocationRetries-1,retry401)
    else
      return response
    end
  end

  def tout(sec, exception=Interrupt)
puts "in tout"
    return yield if sec == nil or sec.zero?
    begin
      x = Thread.current
      y = Thread.start {
puts "sleeping in thread"
STDOUT.flush
sleep 1
puts "sleeping in thread"
STDOUT.flush
sleep 1
puts "sleeping in thread"
sleep 1
STDOUT.flush
puts "sleeping in thread"
sleep 1
STDOUT.flush
        sleep sec
puts "done sleeping"
        x.raise exception, "execution expired" if x.alive?
      }
puts "yielding"
      yield sec
    ensure
      y.kill if y and y.alive?
    end
  end

  ##
  # Performs an HTTP put request and returns the body of response.  Optionally
  # creates a REXML document is the URI returns XML data.
  #
  # uri:: [String] The URI to put to (http://...)
  # request:: [String] The data to put
  # format:: [Symbol=:as_string] Return format (:as_string or :as_xml)
  # return:: [String | REXML::Document] The body test returned as a String or XML document
  #
  def putHtml(uri, data, format=:as_string)
    uri = URI.parse(uri)
    c = Net::HTTP.new(uri.host, uri.port)
    c.read_timeout = 60*30 # per bill wright
    req_uri = uri.path
    req_uri = req_uri+"?"+uri.query if uri.query
    req = Net::HTTP::Put.new(req_uri)
    req.basic_auth(@username, @password)
    result = c.request(req, data)
    return nil unless result
    result = result.body
    return case format
    when :as_xml
      REXML::Document.parse(result)
    else
      result
    end
  end
    
  def checkTomcatServers(hosts, port)
    status = true
    numResponding = 0
    numDown = 0
    hosts.each do |host|
      url = "http://#{host}:#{port}/"
      begin
        response = getHtml(url, 60)
      rescue Exception
        response = nil
      end
      if response and response.status==200
        numResponding = numResponding + 1
        puts "Host #{host} is responding."
      else
        numDown = numDown + 1
        puts "Host #{host} is NOT responding."
        status = false
      end
    end
    if numDown == 0
      puts "All hosts are responding."
    else
      puts "Not all of the hosts are responded (#{numResponding} of #{numResponding+numDown})."
    end
    status
  end

end # SRIWeb


class Net::HTTPResponse
  def code=(code)
    @code = code
  end
  def status
    return Integer(code)
  end
end




=begin

@username = 'ConusUserDomainComm\george'
@password = 'george'
puts getHtml('http://yew:8820/$RootCaManager/CA/RevokeCertificateServlet')


  
  def createResponse(result)
    return MyResponse.new(0, {}, []) unless result.size>0
    result = result.split(/\n/)
    result = result.collect {|l| l.strip}
    isParam = true
    params = []
    lines  = []
    result.each do |l|
      if isParam
        if l.size == 0
          isParam = false
        else
          params << l
        end
      else
        lines << l
      end
    end
    
    codeLine = params[0]
    status = 0
    begin
      status = Integer(codeLine.scan(/[^ ]* ([[:digit:]]{1,3}) /).to_s) if codeLine
    rescue Exception
      puts ['error in createResponse', params, lines]
      status = 0
    end
    params = params[1..-1]
    phash = {}
    params = params.collect do |p|
      array = p.split /: /
      phash[array[0].downcase] = array[1]
    end
    phash['status'] = status
    return MyResponse.new(status, phash, lines)
  end

  
  # Original code is from Rich Kilmer
  def postHtmlAux(uri, data, timeout=30.minutes, content_type="application/x-www-form-urlencoded", relocationRetries=5)
    return nil if uri.nil?
    puts "CURL HTTP POST: [#{uri}]" if $COUGAAR_DEBUG
    # include header, silent (no progress meter/error msgs), timeout len, extra header, user auth, url, output post data as binary
    pipe = IO.popen("curl -i -s --max-time #{timeout} --header 'Content-Type: #{content_type}' #{gen_auth} --url '#{uri}' --data-binary @-", "r+")
    pipe.write(data)
    pipe.close_write
    result = pipe.read
    response = createResponse(result)
puts response.body if response.code==400
    if response.code==302
      location = response.params['location']
      if relocationRetries > 0
        return postHtmlAux(location, timeout, content_type, relocationRetries-1)
      else
        raise "Too many web redirections: '#{uri}'"
      end
    else
      response.params['url'] = uri
      return response
    end
  end
  

  ##
  # Performs an HTTP get request and follows redirects.  This is
  # useful for Cougaar because all agent requests are redirected
  # to the host that the agent is on before returning data.
  #
  # uri:: [String] The uri (http://...)
  # return:: [String, URI] Returns the body of the http response and the URI of the final page returned
  #
  # Original code is from Rich Kilmer
  #
  def getHtmlAux(uri, timeout, relocationTries=5)
    puts "Fetching '#{uri.as_string}'" if $WebVerboseDebugging
    result = `curl -i -s --max-time #{timeout} #{gen_auth} --url '#{uri}'`
    response = createResponse(result)
puts response.body if response.code==400
    if response.code==302
      location = response.params['location']
#      puts "Redirected from #{url} to '#{location}'" if $WebVerboseDebugging
      if relocationTries > 0
        return getHtmlAux(location, timeout, relocationTries-1)
      else
        raise "Too many web redirections: '#{uri}'"
      end
    end
    response.params['url'] = uri
    return response
  end
  
  def postHtml(url, params=[], timeout=300, content_type="application/x-www-form-urlencoded")
    response = postHtmlAux(url, params.join("&"), timeout, content_type)
    raise "No http response" if not response
    return response
  end

  def getHtml(url, timeout=300)
    response = getHtmlAux(url, timeout)
    raise "No http response" if not response
    return response
  end
  

class MyResponse
  # lines is an array of lines which exist in body
  attr_accessor :lines, :body, :code, :params
  def initialize(code, params, lines)
    @lines = lines
    @body = lines.join('\n')
    @code = code
    @params = params
  end
end

  def gen_auth
    auth = nil
    auth = "-u '#{@username}:#{@password}'" if @username!=nil && @password!=nil
    auth = "-u '#{@username}'" if auth==nil && @username!=nil
    auth
  end
  

=end



# this is used only when getHtmlSsl gets an error instead of a response.
class HtmlResponse
  attr_accessor :status, :body
  def initialize(status, body)
    @status = status
    @body = body
    @hash = {}
  end
  def code
    return String(@status)
  end

  def [](name)
    return @hash[name]
  end
  def []=(name, value)
    @hash[name] = value
  end
end
