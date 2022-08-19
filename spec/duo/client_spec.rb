# frozen_string_literal: true

module TestHelpers
	def generate_string_of_length(length)
		length.times.map { "z" }.join
	end
end

RSpec.describe Duo::Client do
	include TestHelpers
	
	let(:client_id) { 'DIXXXXXXXXXXXXXXXXXX' }
	let(:client_secret) { 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' }
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
		end

		it 'allows custom CA certificates to be provided'
		it 'allows a flag to use `duo_code` instead of `code` for the `returned authorisation parameter`'
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

		it 'returns a valid authorisation uri' do
			stubbed_time = Time.now
			allow(Time).to receive(:now).and_return(stubbed_time)

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
end
  