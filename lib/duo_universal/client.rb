require 'jwt'
require 'securerandom'
require 'httparty'

require 'byebug'

module Duo
  class Client
    STATE_LENGTH = 36
    JTI_LENGTH = 36
    MINIMUM_STATE_LENGTH = 22
    MAXIMUM_STATE_LENGTH = 1024
    CLIENT_ID_LENGTH = 20
    CLIENT_SECRET_LENGTH = 40
    CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    JWT_LEEWAY = 60

    attr_reader :client_id, :client_secret, :host, :redirect_uri, :use_duo_code_attribute

    def initialize(client_id, client_secret, host, redirect_uri, optional_args = {})
      raise Duo::ClientIDLengthError unless client_id && client_id.length == CLIENT_ID_LENGTH
      raise Duo::ClientSecretLengthError unless client_secret && client_secret.length == CLIENT_SECRET_LENGTH
      raise Duo::ApiHostRequiredError unless host
      raise Duo::RedirectUriRequiredError unless redirect_uri

      @client_id = client_id
      @client_secret = client_secret
      @host = host
      @redirect_uri = redirect_uri
      @use_duo_code_attribute = optional_args.fetch(:use_duo_code_attribute) { true }
    end

    def api_host_uri
      "https://#{host}"
    end

    def authorize_endpoint_uri
      "https://#{host}/oauth/v1/authorize"
    end

    def health_check_endpoint_uri
      "https://#{host}/oauth/v1/health_check"
    end

    def token_endpoint_uri
      "https://#{host}/oauth/v1/token"
    end

    def create_auth_url(username, state)
      raise Duo::StateLengthError unless state && state.length >= MINIMUM_STATE_LENGTH && state.length <= MAXIMUM_STATE_LENGTH
      raise Duo::UsernameRequiredError unless username && username.gsub(/\s*/, '').length > 0

      jwt_args = {
        scope: 'openid',
        redirect_uri: redirect_uri,
        client_id: client_id,
        iss: client_id,
        aud: api_host_uri,
        exp: (Time.now + (5*60)).to_i,
        state: state,
        response_type: 'code',
        duo_uname: username,
        use_duo_code_attribute: use_duo_code_attribute,
      }

      req_jwt = JWT.encode(jwt_args, client_secret, 'HS512')

      all_args = {
        response_type: 'code',
        client_id: client_id,
        request: req_jwt
      }

      query_string = URI.encode_www_form all_args

      "#{authorize_endpoint_uri}?#{query_string}"
    end

    def generate_state
      SecureRandom.alphanumeric(STATE_LENGTH)
    end

    # Checks whether Duo is available.
    # Returns:
    #  {'response': {'timestamp': <int:unix timestamp>}, 'stat': 'OK'}
    # Raises:
    # 
    def health_check
      req_payload = {
        client_assertion: JWT.encode(jwt_args_for(health_check_endpoint_uri), client_secret, 'HS512'),
        client_id: client_id
      }

      # ToDo: Add Support for verifying SSL certificates
      begin
        res = HTTParty.post(health_check_endpoint_uri, body: req_payload)

        json_resp = JSON.parse res.body

        raise Duo::Error.new(json_resp) unless json_resp['stat'] == 'OK'

        json_resp
      rescue => e
        raise e
      end
    end

    # Exchanges the duo_code for a token with Duo to determine
    # if the auth was successful.
    #	Argument:
    #		duo_code      -- Authentication session transaction id
    #										 returned by Duo
    #		username      -- Name of the user authenticating with Duo
    # 	nonce         -- Random 36B string used to associate
    #										 a session with an ID token
    #	Returns:
    #		A token with meta-data about the auth
    #	Raises:
    #		Duo::Error on error for invalid duo_codes, invalid credentials,
    #		or problems connecting to Duo
    def exchange_authorization_code_for_2fa_result(duo_code, username, nonce = nil)
      raise Duo::DuoCodeRequiredError unless duo_code

      jwt_args = jwt_args_for(token_endpoint_uri)

      all_args = {
        grant_type: 'authorization_code',
        code: duo_code,
        redirect_uri: redirect_uri,
        client_id: client_id,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: JWT.encode(jwt_args, client_secret, 'HS512')
      }

      begin
        user_agent = "duo_universal_ruby/#{Duo::VERSION} ruby/#{RUBY_VERSION}-p#{RUBY_PATCHLEVEL} #{RUBY_PLATFORM}"

        resp = HTTParty.post(token_endpoint_uri, body: all_args, headers: { user_agent: user_agent })

        json_response_body = JSON.parse(resp.body)

        raise Duo::Error.new(json_response_body) unless resp.code == 200

        decoded_token = JWT.decode(json_response_body['id_token'], client_secret, true, { 
          algorithm: 'HS512', 
          iss: token_endpoint_uri, 
          verify_iss: true,  
          aud: client_id,
          verify_aud: true,
          exp_leeway: JWT_LEEWAY,
          required_claims: ['exp', 'iat'],
          verify_iat: true
        }).first

        raise Duo::Error.new("The username is invalid.") unless decoded_token.has_key?('preferred_username') and decoded_token['preferred_username'] == username
        raise Duo::Error.new("The nonce is invalid.") unless decoded_token.has_key?('nonce') and decoded_token['nonce'] == nonce  

        decoded_token
      rescue => e
        raise Duo::Error.new(e.message)
      end
    end

    private

    def jwt_args_for(endpoint_uri)
      {
        iss: client_id,
        sub: client_id,
        aud: endpoint_uri,
        exp: (Time.now + (5*60)).to_i,
        jti: SecureRandom.alphanumeric(JTI_LENGTH)
      }
    end
  end
end