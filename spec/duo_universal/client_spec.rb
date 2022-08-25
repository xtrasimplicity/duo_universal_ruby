# frozen_string_literal: true

module TestHelpers
  def generate_string_of_length(length)
    length.times.map { "z" }.join
  end

  module AuthorizationCodeExchangeHelpers
    def inject_value_into_jwt!(decoded_jwt_payload, key_to_change, new_value)
      decoded_jwt_payload[key_to_change.to_s] = new_value

      decoded_jwt_payload
    end

    def pop_key_from_jwt!(decoded_jwt_payload, key_to_pop)
      [key_to_pop, key_to_pop.to_s].each do |k|
        decoded_jwt_payload.delete k
      end
      
      decoded_jwt_payload
    end

    def build_id_token_from_jwt_payload(decoded_jwt_payload, secret)
      encoded_jwt = JWT.encode(decoded_jwt_payload, secret, 'HS512')

      { id_token: encoded_jwt }
    end

    def stub_token_exchange_http_response(http_response_body, http_response_code = 200)
      stubbed_http_response = double(
        code: http_response_code,
        body: http_response_body.to_json
      )

      expect(HTTParty).to receive(:post).with(subject.token_endpoint_uri, any_args).and_return(stubbed_http_response)
    end
  end
end

RSpec.describe Duo::Client do
  include TestHelpers
  
  let(:client_id) { 'DIXXXXXXXXXXXXXXXXXX' }
  let(:wrong_client_id) { 'DIXXXXXXXXXXXXXXXXXY' }
  let(:client_secret) { generate_string_of_length(Duo::Client::CLIENT_SECRET_LENGTH) }
  let(:host) { 'api-XXXXXXX.test.duosecurity.com' }
  let(:redirect_uri) { 'https://www.example.com' }
  let(:username) { 'user1' }
  let(:state) { 'deadbeefdeadbeefdeadbeefdeadbeefdead' }

  subject { Duo::Client.new(client_id, client_secret, host, redirect_uri) }

  describe 'initialisation' do
    it 'sets the required attributes' do
      expect(subject.client_id).to eq(client_id)
      expect(subject.client_secret).to eq(client_secret)
      expect(subject.host).to eq(host)
      expect(subject.redirect_uri).to eq(redirect_uri)
      expect(subject.use_duo_code_attribute).to eq(true)
    end

    it 'allows custom CA certificates to be provided'
    it 'allows a flag to use `duo_code` instead of `code` for the `returned authorisation parameter`' do
      subject = Duo::Client.new(client_id, client_secret, host, redirect_uri, use_duo_code_attribute: false)

      expect(subject.use_duo_code_attribute).to eq(false)
    end

    describe 'validation' do
      it 'requires the client ID to be present' do
        expect { Duo::Client.new(nil, client_secret, host, redirect_uri) }.to raise_error(Duo::ClientIDLengthError)
      end

      it 'requires the client ID to be of the correct length' do
        client_id_short = generate_string_of_length(Duo::Client::CLIENT_ID_LENGTH - 1)
        client_id_long = generate_string_of_length(Duo::Client::CLIENT_ID_LENGTH + 1)
        
        expect { Duo::Client.new(client_id_short, client_secret, host, redirect_uri) }.to raise_error(Duo::ClientIDLengthError)
        expect { Duo::Client.new(client_id_long, client_secret, host, redirect_uri) }.to raise_error(Duo::ClientIDLengthError)
      end

      it 'requires the client secret to be present' do
        expect { Duo::Client.new(client_id, nil, host, redirect_uri) }.to raise_error(Duo::ClientSecretLengthError)
      end

      it 'requires the client secret to be of the correct length' do
        client_secret_short = generate_string_of_length(Duo::Client::CLIENT_SECRET_LENGTH - 1)
        client_secret_long = generate_string_of_length(Duo::Client::CLIENT_SECRET_LENGTH + 1)
        
        expect { Duo::Client.new(client_id, client_secret_short, host, redirect_uri) }.to raise_error(Duo::ClientSecretLengthError)
        expect { Duo::Client.new(client_id, client_secret_long, host, redirect_uri) }.to raise_error(Duo::ClientSecretLengthError)
      end

      it 'requires the API host to be present' do
        expect { Duo::Client.new(client_id, client_secret, nil, redirect_uri) }.to raise_error(Duo::ApiHostRequiredError)
      end
      
      it 'requires the redirect URI to be present' do
        expect { Duo::Client.new(client_id, client_secret, host, nil) }.to raise_error(Duo::RedirectUriRequiredError)
      end
    end
  end

  describe '#authorize_endpoint_uri' do
    it 'returns the correct URL' do
      expect(subject.authorize_endpoint_uri).to eq("https://#{host}/oauth/v1/authorize")
    end
  end

  describe '#create_auth_url' do
    describe 'validation' do
      it 'requires state to be present' do
        expect { subject.create_auth_url(username, nil) }.to raise_error(Duo::StateLengthError)
      end

      it 'requires state to be of the correct length' do
        state_short = generate_string_of_length(Duo::Client::MINIMUM_STATE_LENGTH - 1)
        state_long = generate_string_of_length(Duo::Client::MAXIMUM_STATE_LENGTH + 1)
        state_max_length = generate_string_of_length(Duo::Client::MAXIMUM_STATE_LENGTH)
        state_min_length = generate_string_of_length(Duo::Client::MINIMUM_STATE_LENGTH)

        expect { subject.create_auth_url(username, state_short) }.to raise_error(Duo::StateLengthError)
        expect { subject.create_auth_url(username, state_long) }.to raise_error(Duo::StateLengthError)

        expect { subject.create_auth_url(username, state_max_length) }.not_to raise_error
        expect { subject.create_auth_url(username, state_min_length) }.not_to raise_error
      end


      it 'requires a username to be present' do
        expect { subject.create_auth_url(nil, state) }.to raise_error(Duo::UsernameRequiredError)
        expect { subject.create_auth_url(" ", state) }.to raise_error(Duo::UsernameRequiredError)
      end
    end

    let(:stubbed_time) { Time.now }

    before do
      allow(Time).to receive(:now).and_return(stubbed_time)
    end

    context 'when `use_duo_code_attribute` is not specified on client instantiation' do
      it 'returns a valid authorisation uri' do
        jwt_args = {
          scope: 'openid',
          redirect_uri: redirect_uri,
          client_id: client_id,
          iss: client_id,
          aud: subject.api_host_uri,
          exp: (Time.now + (5*60)).to_i,
          state: state,
          response_type: 'code',
          duo_uname: username,
          use_duo_code_attribute: true
        }
  
        expected_args = {
          response_type: 'code',
          client_id: client_id,
          request: JWT.encode(jwt_args, client_secret, 'HS512')
        }
  
        encoded_expected_args = URI.encode_www_form expected_args
  
        expected_authorisation_url = "#{subject.authorize_endpoint_uri}?#{encoded_expected_args}"
  
        actual_authorisation_url = subject.create_auth_url(username, state)
  
        expect(actual_authorisation_url).to eq(expected_authorisation_url)
      end
    end

    context 'when `use_duo_code_attribute` is set to `false` on client instantiation' do
      subject { Duo::Client.new(client_id, client_secret, host, redirect_uri, use_duo_code_attribute: false) }

      it 'returns a valid authorisation uri' do
        jwt_args = {
          scope: 'openid',
          redirect_uri: redirect_uri,
          client_id: client_id,
          iss: client_id,
          aud: subject.api_host_uri,
          exp: (Time.now + (5*60)).to_i,
          state: state,
          response_type: 'code',
          duo_uname: username,
          use_duo_code_attribute: false
        }
  
        expected_args = {
          response_type: 'code',
          client_id: client_id,
          request: JWT.encode(jwt_args, client_secret, 'HS512')
        }
  
        encoded_expected_args = URI.encode_www_form expected_args
  
        expected_authorisation_url = "#{subject.authorize_endpoint_uri}?#{encoded_expected_args}"
  
        actual_authorisation_url = subject.create_auth_url(username, state)
  
  
        expect(actual_authorisation_url).to eq(expected_authorisation_url)
      end
    end
  end

  describe '#generate_state' do
    it 'generates a random alphanumeric string of the correct length' do
      stubbed_state = SecureRandom.alphanumeric(Duo::Client::STATE_LENGTH)

      expect(SecureRandom).to receive(:alphanumeric).with(Duo::Client::STATE_LENGTH).and_return(stubbed_state)

      actual_state = subject.generate_state

      expect(actual_state).to eq(stubbed_state)
      expect(actual_state.length).to eq(Duo::Client::STATE_LENGTH)
    end
  end

  describe '#health_check' do
    let(:stubbed_time) { Time.now }

    before do
      allow(Time).to receive(:now).and_return(stubbed_time)
    end

    it 'handles timeout errors' do
      expect(HTTParty).to receive(:post).with(any_args).and_raise(Net::OpenTimeout)
      
      expect { subject.health_check }.to raise_error(Net::OpenTimeout)
    end

    it 'handles when duo is not able to be contacted (e.g. network is down)'
    
    it 'handles bad client IDs' do
      client_with_bad_id = Duo::Client.new(wrong_client_id, client_secret, host, redirect_uri)

      expected_response_as_json = {
        message: 'invalid_client',
        code: 40002,
        stat: 'FAIL',
        message_detail: 'The provided client_assertion was invalid.',
        timestamp: stubbed_time.to_i
      }.to_json

      stubbed_json_response = double(body: expected_response_as_json)

      expect(HTTParty).to receive(:post).with(any_args).and_return(stubbed_json_response)

      expect { subject.health_check }.to raise_error(Duo::Error)
    end

    it 'handles bad Duo Certificates'

    it 'handles when everything is successful' do
      stubbed_JTI_value = SecureRandom.alphanumeric(Duo::Client::JTI_LENGTH)

      expect(SecureRandom).to receive(:alphanumeric).with(Duo::Client::JTI_LENGTH).and_return(stubbed_JTI_value)

      expected_request_payload = {
        client_assertion: JWT.encode({
          iss: client_id,
          sub: client_id,
          aud: subject.health_check_endpoint_uri,
          exp: (stubbed_time + 300).to_i,
          jti: stubbed_JTI_value
          },
          client_secret,
          'HS512'
        ),
        client_id: client_id,
      }

      expected_json_response = {
        response: {
          timestamp: stubbed_time.to_i,
        },
        stat: 'OK'
      }.to_json

      expect(HTTParty).to receive(:post).with(subject.health_check_endpoint_uri, body: expected_request_payload).and_return(
        double(body: expected_json_response)
      )

      expect(subject.health_check).to eq(JSON.parse(expected_json_response))
    end
  end

  describe '#exchange_authorization_code_for_2fa_result' do
    include TestHelpers::AuthorizationCodeExchangeHelpers

    let(:stubbed_time) { Time.now }
    let(:duo_code) { 'deadbeefdeadbeefdeadbeefdeadbeef' }
    let(:nonce) { 'abcdefghijklmnopqrstuvwxyzabcdef' }
    let(:wrong_nonce) { nonce.reverse }
    let(:decoded_jwt) do
      {
        'auth_result' => {
          'result' => 'allow',
          'status' => 'allow',
          'status_msg' => 'Login Successful',
        },
        'aud' => client_id,
        'auth_time' => stubbed_time.to_i,
        'exp' => (stubbed_time + 300).to_i,
        'iat' => (stubbed_time).to_i,
        'iss' => subject.token_endpoint_uri,
        'preferred_username' => username,
        'nonce' => nonce,
      }
    end

    before do
      allow(Time).to receive(:now).and_return(stubbed_time)
    end


    it 'raises an error if no duo_code is provided' do
      expect { subject.exchange_authorization_code_for_2fa_result(nil, username) }.to raise_error(Duo::DuoCodeRequiredError)
    end

    it 'raises an error if the request times out'
    it 'raises an error if the network connection failed'
    
    it 'raises an error if a bad client ID is provided' do
      stubbed_http_response = double(
        code: 400,
        body: {
          error: 'invalid_client',
          error_description: 'Invalid Client assertion: The `iss` claim must match the supplied client_id'
        }.to_json
      )

      expect(HTTParty).to receive(:post).with(subject.token_endpoint_uri, any_args).and_return(stubbed_http_response)

      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error, /invalid_client/i)
    end

    it 'raises an error if a bad duo_code is provided' do
      stubbed_http_response = double(
        code: 400,
        body: {
          error: 'invalid_grant',
          error_description: 'The provided authorization grant or refresh token is invalid, expired, revoked, does not match the redirection URI.'
        }.to_json
      )

      expect(HTTParty).to receive(:post).with(subject.token_endpoint_uri, any_args).and_return(stubbed_http_response)

      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error, /invalid_grant/i)
    end

    it 'raises an error if an invalid duo Cert is found when connecting'

    it 'raises an error when a token has been signed with the wrong secret' do
      encoded_jwt = JWT.encode(decoded_jwt, wrong_client_id, 'HS512')
      id_token = { id_token: encoded_jwt }

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error, /Signature verification failed/i)
    end

    it 'raises an error if an invalid preferred name is provided' do
      inject_value_into_jwt! decoded_jwt, :preferred_username, 'wrong_username'

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error)
    end

    it 'raises an error if a preferred name is not provided' do
      pop_key_from_jwt! decoded_jwt, :preferred_username

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error)
    end

    it 'raises an error if an invalid audience is provided' do
      inject_value_into_jwt! decoded_jwt, :preferred_username, 'wrong_username'

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error)
    end

    it 'raises an error if no audience is provided' do
      pop_key_from_jwt! decoded_jwt, :aud

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error)
    end

    it 'raises an error if an invalid issuer is provided' do
      inject_value_into_jwt! decoded_jwt, :iss, host
      
      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error)
    end

    it 'raises an error if an IAT is not provided' do
      pop_key_from_jwt! decoded_jwt, :iat

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error)
    end
    
    it 'raises an error if an expiration is not provided' do
      pop_key_from_jwt! decoded_jwt, :exp

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error)
    end

    it 'raises an error if an expiration has passed' do
      inject_value_into_jwt! decoded_jwt, :exp, 1

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username) }.to raise_error(Duo::Error)
    end

    it 'raises an error if an invalid nonce is provided' do
      inject_value_into_jwt! decoded_jwt, :nonce, wrong_nonce

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username, nonce) }.to raise_error(Duo::Error, /The nonce is invalid/i)
    end

    it 'raises an error if no nonce is provided' do
      pop_key_from_jwt! decoded_jwt, :nonce

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username, nonce) }.to raise_error(Duo::Error, /The nonce is invalid/i)
    end

    it 'raises an error if a username is not provided' do
      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, nil) }.to raise_error(Duo::Error)
    end

    it 'returns a successful JWT when authorisation succeeds' do
      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)

      actual_jwt = subject.exchange_authorization_code_for_2fa_result(duo_code, username, nonce)

      expect(actual_jwt).to eq(decoded_jwt)
    end

    it 'succeeds when a good nonce is provided' do
      inject_value_into_jwt! decoded_jwt, :nonce, nonce

      id_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(id_token)
      
      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username, nonce) }.not_to raise_error
    end

    it 'fails signature validation when an altered token is received' do
      other_jwt = decoded_jwt
      other_jwt['preferred_username'] = 'some_other_user'

      altered_token = build_id_token_from_jwt_payload decoded_jwt, client_secret

      stub_token_exchange_http_response(altered_token)

      expect { subject.exchange_authorization_code_for_2fa_result(duo_code, username, nonce) }.to raise_error(Duo::Error)
    end
  end
end