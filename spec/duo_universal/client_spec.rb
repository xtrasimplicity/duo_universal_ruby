# frozen_string_literal: true

module TestHelpers
  def generate_string_of_length(length)
    length.times.map { "z" }.join
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
end
