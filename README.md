# Auth0 app to list rules for each application

This app will generate a list of the applications in your auth0 tenant and the rules that apply to each application. This solution is protected by Auth0 authentication, and only available to a selected whitelist of users.

## Creating the app

1. From your [Auth0's dashboard](https://manage.auth0.com/#/), on the left sidebar, click on Applications -> Applications and then click the button '+ Create Application'
2. Enter a name for this app (ex. 'GeneratedListOfRules') and select 'Regular Web App' from the options available. When prompted on the technology to use for this app, select 'Ruby On Rails'.
3. From the application details screen, go to settings and scroll down to 'Application URIs' and register `http://localhost:3000/auth/auth0/callback` as `Allowed Callback URLs` and  `http://localhost:3000/` as `Allowed Logout URLs`. Note: Replace localhost:3000 with your domain after deploying this application. 
   
## Accessing Auth0 management API

1. From your [Auth0's dashboard](https://manage.auth0.com/#/), on the left sidebar, click on Applications -> API and then select the Auth0 Management API.
2. Go to Machine to Machine Applications and scroll down to the app that you have just created and set the toggle switch on the right to 'Authorized.'
3. Then select the dropdown arrow for that app so see a list of permissions available for this app. Check the boxes for 'read:clients' and 'read:rules.'

## Adding Rules List Functionality

There are two options for how to implement this app. You will need [Ruby](https://www.ruby-lang.org/en/documentation/installation/) installed to run this app on your local server. 

### Option 1: Clone this App

1. Fork and clone this repo, cd into the directory and open it in your code editor. 
2. Next, set the environment variables by creating a .env file and adding your Domain, Client ID, and Client Secret in the following format:  

````bash
# .env file
AUTH0_CLIENT_ID=YOUR_CLIENT_ID
AUTH0_CLIENT_SECRET=YOUR_CLIENT_SECRET
AUTH0_DOMAIN=<YOUR_TENANT>.auth0.com
AUTH0_CALLBACK_URL=http://localhost:3000/auth/auth0/callback
````
3. Your Domain, Client ID and Client Secret can be found in your Application Settings on your Auth0 Dashboard.
4. Once you've set those 4 environment variables, run `bundle install`.
5. To run the app on your local server, run `rails s`, and then browse [http://localhost:3000/](http://localhost:3000/).


### Option 2: Download Sample App and Add Code

1. Go back to Applications -> Applications in the sidebar and select the newly created application, click on 'Quick Start' and then click on the 'Download Sample' button.
2. From your terminal, cd into the example-app directory, open it in your code editor, and run `bundle install`. 
3. Replace the code in app/controllers/dashboard_controller.rb with the following: 
```` ruby
# app/controllers/dashboard_controller.rb

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
````

1. Then replace the code in app/views/dashboard/show.html.erb with the following:
```` ruby
# app/views/dashboard/show.html.erb

<section class="jumbotron  text-center">
  <h2><img class="jumbo-thumbnail" src="<%= @user.picture %>"/></h2>
  <h1>Welcome, <%= @user.name %></h1>
</section>
<section class="container">
  <div class="panel panel-default">
    <div class="panel-heading">Applications and applicable rules</div>
    <div class="panel-body">
      <table class="table table-striped">
        <tr>
          <th>Applications</th>
          <th>Rules</th>
        </tr>        
      <% @pairs.each do |client, rules| %>
        <tr>
          <td><%= client["name"] %></td> 
          <td>
            <% rules.each do |rule| %>
              <li><%= rule %> </li> 
            <% end %> 
          </td>
        </tr>   
      <% end %>
      </table>
    </div>
  </div>
</section>

````

## Adding a whitelist of users for this app

1. From your [Auth0's dashboard](https://manage.auth0.com/#/), on the left sidebar, click on Auth Pipeline -> Rules and then click the button '+ Create Rule'.
2. From the rule templates, find the Access Control templates and select 'Whitelist for Specific App.'
3. Name the rule (ex. Whitelist for Rules List App), and addd the emails of the users who you would like to authorize to the 'whitelist' array: 
```` js
function userWhitelistForSpecificApp(user, context, callback) {
  // Access should only be granted to verified users.
  if (!user.email || !user.email_verified) {
    return callback(new UnauthorizedError('Access denied.'));
  }

  // only enforce for NameOfTheAppWithWhiteList
  // bypass this rule for all other apps
  if (context.clientName !== 'NameOfTheAppWithWhiteList') {
    return callback(null, user, context);
  }

  const whitelist = ['user1@example.com', 'user2@example.com']; // authorized users
  const userHasAccess = whitelist.some(function (email) {
    return email === user.email;
  });

  if (!userHasAccess) {
    return callback(new UnauthorizedError('Access denied.'));
  }

  callback(null, user, context);
}
````





