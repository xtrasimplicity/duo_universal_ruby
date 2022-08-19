require 'jwt'

module Duo
	class Client
		MINIMUM_STATE_LENGTH = 22
		MAXIMUM_STATE_LENGTH = 1024

		attr_reader :client_id, :client_secret, :host, :redirect_uri

		def initialize(client_id, client_secret, host, redirect_uri)
			@client_id = client_id
			@client_secret = client_secret
			@host = host
			@redirect_uri = redirect_uri
		end

		def api_host_uri
			"https://#{host}"
		end

		def authorize_endpoint_uri
			"https://#{host}/oauth/v1/authorize"
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
				use_duo_code_attribute: true,
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
	end
end