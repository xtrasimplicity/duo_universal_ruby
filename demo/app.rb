require 'rubygems'
require 'bundler/setup'

require 'yaml'
require 'sinatra'
require 'duo_universal'
require 'byebug'

duo_config = YAML.load_file(File.join(__dir__, 'duo.yaml'))

@@duo_client = Duo::Client.new(
  duo_config['client_id'],
  duo_config['client_secret'],
  duo_config['api_host'],
  duo_config['redirect_uri']
)

get '/' do
 erb :index
end

post '/login' do
  username = params[:username]
  password = params[:password]

  begin
    puts "Performing Health check..."
    @@duo_client.health_check

    # ToDo: Support failing open

    state = @@duo_client.generate_state
    session[:state] = state
    session[:username] = username

    redirect @@duo_client.create_auth_url(username, state)
  rescue => e
    @message = e.message
    erb :index
  end
end

get '/duo-cb' do
  state = params[:state]
  code = params[:duo_code]

  if session[:state].nil? || session[:username].nil?
    @message = "You must authenticate before you can receive a Duo Callback."
    erb :index
  end

  if state != session[:state]
    @message = "Duo state does not match saved state!"
    erb :index
  end

  decoded_token = @@duo_client.exchange_authorization_code_for_2fa_result(code, session[:username])


  @message = "Success!"
  erb :index
end