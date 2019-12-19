module Peatio::Ranger
  class Connection
    attr_reader :socket, :user, :authorized, :streams, :logger, :id

    def initialize(authenticator, router, socket, logger)
      @id = SecureRandom.hex(10)
      @authenticator = authenticator
      @router = router
      @socket = socket
      @logger = logger
      @user = nil
      @authorized = false
      @streams = {}
    end

    def inspect
      if authorized
        "<Connection id=#{id} user=#{user}>"
      else
        "<Connection id=#{id}>"
      end
    end

    def send_raw(payload)
      if user
        logger.debug { "sending to user #{user.inspect} payload: #{payload}" }
      else
        logger.debug { "sending to anonymous payload: #{payload}" }
      end
      @socket.send(payload)
    end

    def send(method, data)
      payload = JSON.dump(method => data)
      send_raw(payload)
    end

    def authenticate(jwt)
      payload = {}
      authorized = false
      begin
        payload = @authenticator.authenticate!(jwt)
        authorized = true
      rescue Peatio::Auth::Error => e
        logger.warn e.message
      end
      [authorized, payload]
    end

    def subscribe(subscribed_streams)
      raise "Streams must be an array of strings" unless subscribed_streams.is_a?(Array)

      subscribed_streams.each do |stream|
        stream = stream.to_s
        next if stream.empty?

        unless @streams[stream]
          @streams[stream] = true
          @router.on_subscribe(self, stream)
        end
      end
      send(:success, message: "subscribed", streams: streams.keys)
    end

    def unsubscribe(unsubscribed_streams)
      raise "Streams must be an array of strings" unless unsubscribed_streams.is_a?(Array)

      unsubscribed_streams.each do |stream|
        stream = stream.to_s
        next if stream.empty?

        if @streams[stream]
          @streams.delete(stream)
          @router.on_unsubscribe(self, stream)
        end
      end
      send(:success, message: "unsubscribed", streams: streams.keys)
    end

    def handle(msg)
      return if msg.to_s.empty?

      if msg =~ /^ping/
        send_raw("pong")
        return
      end

      data = JSON.parse(msg)

      unless data["jwt"].to_s.empty?
        @authorized, payload = authenticate(data["jwt"])

        unless @authorized
          send :error, message: "Authentication failed."
          logger.debug "Authentication failed for UID:#{payload[:uid]}"
        else
          @user = payload[:uid]
          @router.on_connection_authenticate(self)
          logger.info "User #{@user} authenticated #{@streams}"
          send :success, message: "Authenticated."
        end
      end

      case data["event"]
      when "subscribe"
        subscribe(data["streams"])
      when "unsubscribe"
        unsubscribe(data["streams"])
      end
    rescue JSON::ParserError => e
      logger.debug { "#{e}, msg: `#{msg}`" }
    end

    def handshake(hs)
      query = URI.decode_www_form(hs.query_string)
      subscribe(query.map {|item| item.last if item.first == "stream" })
      logger.debug "WebSocket connection opened"
      headers = hs.headers_downcased
      return unless headers.key?("authorization")

      @authorized, payload = authenticate(headers["authorization"])

      unless @authorized
        logger.debug "Authentication failed for UID:#{payload[:uid]}"
        raise EM::WebSocket::HandshakeError, "Authorization failed"
      else
        @user = payload[:uid]
        logger.debug "User #{@user} authenticated #{@streams}"
      end
    end
  end
end
