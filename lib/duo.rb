# frozen_string_literal: true

require_relative "duo/version"
require_relative "duo/client"

module Duo
  class Error < StandardError; end
  class StateLengthError < StandardError; end
  class UsernameRequiredError < StandardError; end
end
