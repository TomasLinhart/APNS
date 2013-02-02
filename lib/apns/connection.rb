module APNS
  class Connection
    attr_accessor :socket, :ssl

    def initialize(opts)
      self.socket = TCPSocket.new(opts[:host], opts[:port])

      configure_ssl opts[:pem], opts[:pass]
    end

    def close
      ssl.close
      socket.close
    end

  private

    def configure_ssl(pem, pass)
      raise "The path to your pem file does not exist!" unless File.exist?(pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(pem), pass)
    
      self.ssl     = OpenSSL::SSL::SSLSocket.new(socket, context)
      ssl.connect
    end

  end

  class NotificationConnection < Connection
    def send_notifications(notifications)      
      notifications.each do |n|
        ssl.write n.packaged_notification
      end
    end
  end

  class FeedbackConnection < Connection
    def feedback
      apns_feedback = []

      while (message = ssl.read(38))
        timestamp, token_size, token = message.unpack('N1n1H*')
        apns_feedback << [Time.at(timestamp), token]
      end
     
      apns_feedback
    end
  end
end