class DashboardController < ApplicationController
  include Secured

  def show
    @user = session[:userinfo]
    get_token
    @pairs = set_pairs
  end

  private
  AUTH0_CONFIG = Rails.application.config_for(:auth0)
  
  def get_token
    url = URI("https://#{AUTH0_CONFIG['auth0_domain']}/oauth/token")
    
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Post.new(url)
    request["content-type"] = 'application/json'
    request.body = "{\"client_id\":\"#{AUTH0_CONFIG['auth0_client_id']}\",\"client_secret\":\"#{AUTH0_CONFIG['auth0_client_secret']}\",\"audience\":\"https://#{AUTH0_CONFIG['auth0_domain']}/api/v2/\",\"grant_type\":\"client_credentials\"}"

    response = http.request(request)
    @token = JSON.parse(response.read_body)["access_token"]
  end

  def get_clients
    url = URI("https://#{AUTH0_CONFIG['auth0_domain']}/api/v2/clients")

    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    
    request = Net::HTTP::Get.new(url)
    request["content-type"] = 'application/json'
    request["authorization"] = "Bearer #{@token}" 
    
    response = http.request(request)
    json_response = JSON.parse(response.read_body)
  end

  def get_rules
    url = URI("https://#{AUTH0_CONFIG['auth0_domain']}/api/v2/rules")

    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    
    request = Net::HTTP::Get.new(url)
    request["content-type"] = 'application/json'
    request["authorization"] = "Bearer #{@token}" 
    
    response = http.request(request)
    JSON.parse(response.read_body)
  end

  def set_pairs
    pairs = {}
    rules_applying_to_all_clients = []
    clients = get_clients
    rules = get_rules

    rules.each do |rule|
      if rule["script"].include?('context.clientName') || rule["script"].include?('context.clientID')       
        clients.each do |client|         
          if rule["script"].include?(client["name"]) || rule["script"].include?(client["client_id"])                                  
            if pairs[client]
              pairs[client] = [pairs[client], rule["name"]]
            else
              pairs[client] = rule["name"]
            end
          end
        end
      else
        rules_applying_to_all_clients << rule["name"]
      end
    end

    clients.each do |client|
      if pairs[client]       
        pairs[client] = [pairs[client], rules_applying_to_all_clients].flatten(1)
      else 
        pairs[client] = rules_applying_to_all_clients
      end
    end   
    pairs
  end
end
