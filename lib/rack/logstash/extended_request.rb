require 'rack/request'

module Rack
  class Request
    def path_info_and_query_string
      path_info + (query_string.empty? ? '' : '?' + query_string)
    end

    def http_version
      return nil if server_protocol.nil?
      match_data = server_protocol.match(%r{^HTTP/(.*)$})
      match_data[1] if match_data
    end

    def server_protocol
      @env['SERVER_PROTOCOL']
    end
  end
end
