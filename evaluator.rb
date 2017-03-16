require 'selenium-webdriver'
require 'nokogiri'
require 'net/http'
require 'cgi'

BASE_PLACE = '/xss-danger-evaluator/'
TARGET_PLACE =  BASE_PLACE + 'targets/'
ROOT_DIR = 'C:\\xampp\\htdocs' +  TARGET_PLACE.gsub("/","\\")
BASE_URL = 'http://localhost' + TARGET_PLACE

if ARGV.empty? then
  puts 'Usage: ruby evaluator.rb vulnerablities.php'
  exit
end

path = ARGV.shift.gsub(ROOT_DIR,'').gsub("\\","/")

file_list = [ path ]
resps = file_list.map{|path| [path, Net::HTTP.get_response(URI(BASE_URL + path))]}
htmls = resps.map do |path,resp|
  begin
    [ path, Nokogiri.parse(resp.body) ]
  rescue
    [path, nil]
  end
end.select{|path,html| html}
params = htmls.map do |path, html|
  [ path, 
  html.css("form").map do |form|
        { method: form.attr("method"), action: form.attr("action"), 
	  inputs: (form.css("textarea")+form.css("input")+form.css("select")).map{|input| input.attr("name")}.select{|input|input} }
  end ]
end

form = params[0][1][0]
method = form[:method] || "get"
postparam_names = getparam_names = []
if method.downcase == "post"
  postparam_names= form[:inputs]
else
  getparam_names = form[:inputs]
end

exploit_list = open("src/exploitlist.txt").read.split("\n").map{|exp| exp.gsub(/\\x[0-9a-fA-F]{2}/){|s| s[2,2].hex.chr}}

res = {}

[:firefox, :edge, :chrome, :ie].each do |agent|
  res[agent] = :none
  driver = Selenium::WebDriver.for agent
  driver.get( URI("http://localhost" + BASE_PLACE + "attack.php") + "?target=http://localhost/onsen_v2/onsen4/main.php")
  exploit_list.each do |exploit|
    loop{sleep 0.3;driver.switch_to.alert.accept} rescue driver.get (URI("http://localhost" + BASE_PLACE + "attack.php") + 
      ("?target=" + CGI.escape(BASE_URL + path + "?" + getparam_names.map{|name| name + "=" + CGI.escape(exploit)}.join('&')) + 
         postparam_names.map{|name| "&post_params[" + name +"]=" + CGI.escape(exploit)}.join ))
    sleep 1 unless agent == :chrome
    begin
      alert_text = nil
      alert = driver.switch_to.alert
      alert_text = alert.text || ""
      alert.accept
    rescue Selenium::WebDriver::Error::NoSuchAlertError => e
    rescue => e
    end
    
    if alert_text
      res[agent] = :alert if res[agent] == :none
      cookie = driver.execute_script("return document.cookie;")
      break if cookie.split.join.empty? 
      if alert_text.include?(cookie)
        res[agent] = :cookie if res[agent] == :alert
        break
      end
    end
  end
  loop{sleep 0.3;driver.switch_to.alert.accept} rescue driver.quit
end


pt = {
  cookie: 0.5 * (1- (1-1)*(1-0.2)*(1-0.1)),
  alert:  0.5 * (1- (1-0)*(1-0.2)*(1-0.1)),
  none:   0.0,
}

share = {
 firefox: 10.06,
 chrome:  41.71,
 edge:    4.13,
 ie:      41.33,
}

point = res.map{|browser, result| share[browser] * pt[result]}.inject(:+)

puts point
p res
