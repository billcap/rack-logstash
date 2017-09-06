require 'rack/logstash/extended_request'
require 'rack/logstash/transport'
require 'ipaddr'
require 'socket'
require 'English'

module Rack
  class Logstash
    def initialize(app, url, opts = {})
      @app = app
      @server = Rack::Logstash::Transport.new(url)
      @tags = opts.fetch(:tags, [])
      @custom = opts.fetch(:custom, {})
    end

    def call(env)
      env['rack.logstash.start_time'] = Time.now

      begin
        @app.call(env).tap do |response|
          begin
            log_request(env, response)
          rescue StandardError => ex
            $stderr.puts "Failed to log request: #{ex.message} (#{ex.class})"
            $stderr.puts(ex.backtrace.map { |l| "  #{l}" })
          end
        end
      rescue StandardError => ex
        log_exception(env, ex)
        raise
      end
    end

    private

    def log_request(env, response)
      @server.send(request_log_entry(env, response))
    end

    def request_log_entry(env, response)
      req = Rack::Request.new(env)
      res = Rack::Response.new(response[2], response[0], response[1])

      common_entry_fields(env).tap do |e|
        e['message'] = "#{req.ip} #{req.request_method} #{req.path_info_and_query_string} "\
                        "#{req.server_protocol} => #{res.status}"
        e['ident'] = '-'
        e['auth'] = '-'
        e['response'] = res.status
        e['bytes'] = res.length

        # Log request details if we got a bad request
        if response.first >= 400 && response.first != 404
          e.merge!(request_detail_fields(env))
        end

        # Log response details if we got a bad response
        e.merge!(response_detail_fields(res)) if response.first >= 500
      end
    end

    def log_exception(env, ex)
      @server.send(exception_log_entry(env, ex))
    end

    def exception_log_entry(env, ex)
      req = Rack::Request.new(env)

      common_entry_fields(env).tap do |e|
        e['message'] = "#{req.ip} #{req.request_method} #{req.path_info_and_query_string} #{req.server_protocol} "\
                         "=> #{ex.message} (#{ex.class})"

        e['exception'] = {
          'class' => ex.class,
          'message' => ex.message,
          'backtrace' => ex.backtrace
        }

        e['pwd'] = Dir.getwd

        e.merge!(request_detail_fields(env))
      end
    end

    def common_entry_fields(env)
      req = Rack::Request.new(env)
      {
        '@version' => 1,
        'type' => 'rack-logstash',
        'tags' => @tags,
        'clientip' => req.ip,
        'timestamp' => iso_time(env['rack.logstash.start_time']),
        '@timestamp' => iso_time(env['rack.logstash.start_time']),
        'verb' => req.request_method,
        'request' => req.path_info_and_query_string,
        'httpversion' => req.http_version,
        'rawrequest' => "#{req.request_method} #{req.path_info_and_query_string} #{req.server_protocol}",
        'referrer' => req.referer,
        'agent' => req.user_agent,
        'time_duration' => ((Time.now - env['rack.logstash.start_time']) * 1000).round,
        'host' => Socket.gethostname,
        'pid' => $PROCESS_ID,
        'program' => $PROGRAM_NAME,
        'request_header_host' => req.host
      }.tap do |e|
        # Some conditionally set entries
        ip = IPAddr.new(e['clientip'])
        e['client_ip_v4'] = ip.to_s if ip.ipv4?
        e['client_ip_v6'] = ip.to_s if ip.ipv6?
        @custom.each { |key, value| e[key.to_s] = value }
      end
    end

    def request_detail_fields(env)
      {}.tap do |e|
        io = env['rack.input']
        if io
          io.rewind if io.respond_to? :rewind
          e['request_body'] = io.read
          io.rewind if io.respond_to? :rewind
        end

        e['rack_environment'] = rack_environment(env)
      end
    end

    def rack_environment(env)
      Hash[
        env.map do |key, value|
          unless value.is_a?(Hash) || value.is_a?(Array) || value.is_a?(String) || value.is_a?(Numeric)
            next nil
          end

          value = 'Basic *filtered*' if key == 'HTTP_AUTHORIZATION' && value =~ /^Basic /

          [key, value]
        end.compact
      ]
    end

    def response_detail_fields(res)
      {
        'response_headers' => res.headers,
        'response_body' => res.body.join
      }
    end

    def iso_time(t)
      t.utc.strftime('%FT%T.%LZ')
    end
  end
end
