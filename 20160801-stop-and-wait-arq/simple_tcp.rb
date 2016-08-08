require 'packetfu'
require 'uri'
require 'resolv'

class SimpleTCP
  attr_accessor :role,
                :debug,
                :config,
                :state,
                :send_state,
                :dst_ip,
                :dst_port,
                :src_ip,
                :src_port,
                :self_seq_no,
                :the_other_seq_no,
                :last_sent_ack_no,
                :send_buffer,
                :receiver_buffer,
                :rtt

  CLOSED_STATE = "CLOSED".freeze
  SYN_SENT_STATE = "SYN-SENT".freeze
  ESTABLISHED_STATE = "ESTABLISHED".freeze
  LAST_ACK_STATE = "LAST-ACK".freeze
  FIN_WAIT_1_STATE = 'FIN-WAIT-1'.freeze
  FIN_WAIT_2_STATE = 'FIN-WAIT-2'.freeze
  TIME_WAIT_STATE = 'TIMEWAIT'.freeze
  CLOSE_WAIT_STATE = 'CLOSE_WAIT'.freeze

  LISTEN_STATE = 'LISTEN'.freeze
  SYN_RECEIVED_STATE = 'SYN-RECEIVED'.freeze

  READY_STATE = 'READY'.freeze
  BLOCKING_STATE = 'BLOCKING'.freeze

  def initialize role
    @role = role.to_sym
    @debug = false#true

    @state = CLOSED_STATE
    @self_seq_no = generate_seq_no
    @the_other_seq_no = nil

    @send_state = BLOCKING_STATE
    @send_buffer = nil
    @receiver_buffer = ''
    @rtt = 10

    @config = PacketFu::Utils.whoami?

    @src_ip = @config[:ip_saddr]
    @src_port = 10086
  end

  def set_dst ip, port
    @dst_ip = ip
    @dst_port = port.to_i
  end

  def send_packet flags = [], payload = nil
    if flags.empty?
      raise "#{__method__}: At least 1 flag should be set"
    end

    packet = PacketFu::TCPPacket.new(config: @config)
    packet.ip_saddr = @src_ip
    packet.tcp_sport = @src_port
    packet.ip_daddr = @dst_ip
    packet.tcp_dst = @dst_port
    packet.tcp_seq = @self_seq_no
    packet.tcp_ack = flags.include?(:ack) ? @last_sent_ack_no : 0

    flags.each {|flag| packet.tcp_flags.send("#{flag}=".to_sym, 1) }

    if payload and payload.size > 0
      packet.payload = payload
      @self_seq_no += payload.size
    end

    packet.recalc
    packet.to_w

    debugger "#{__method__}: Sent packet #{packet.inspect}"
  end

  def send_syn
    send_packet [:syn]
    @state = SYN_SENT_STATE
  end

  def send_ack flags = [], payload = ''
    send_packet (flags.to_a + [:ack]), payload
  end

  def connect ip_and_port, &block
    ip, port = ip_and_port.split ':'
    set_dst ip, port

    # listen
    Thread.new {self.listener}

    # start the handshake
    send_syn

    # debug
    Thread.new {self.state_watcher}

    until @state == ESTABLISHED_STATE
      sleep 0.001
    end

    block.call
  end

  def close
    if @role == :server
      @state = LISTEN_STATE
    else
      @state = CLOSED_STATE
    end
  end

  def goodbye
    while @send_state != READY_STATE
      sleep 0.001
    end

    send_fin

    while @state != CLOSED_STATE
      sleep 0.001
    end

    debugger 'exit'
  end

  def send_fin
    send_packet [:fin]
    @state = FIN_WAIT_1_STATE
    @send_state = BLOCKING_STATE
  end

  def handle packet
    begin
      debugger "#{__method__}: Got packet #{packet.inspect}"

      if @state != FIN_WAIT_1_STATE and @state != FIN_WAIT_2_STATE
        if @last_sent_ack_no and (@last_sent_ack_no != packet.tcp_seq)
          debugger "#{__method__}: Got a packet w/ last_sent_ack_no != packet.tcp_seq, drop"
          return
        end
      end

      #debugger "======#{@last_sent_ack_no.to_s 16}" if @last_sent_ack_no
      #debugger (packet.tcp_seq.to_s 16)
      #debugger "#{get_seq_no(packet).to_s 16}"
      @last_sent_ack_no = [get_seq_no(packet), @last_sent_ack_no.to_i].max

      tcp_flags = packet.tcp_flags

      if tcp_flags.rst == 1
        close
        exit

      elsif tcp_flags.syn == 1
        if @state == LISTEN_STATE
          @state = SYN_RECEIVED_STATE
          set_dst packet.ip_saddr, packet.tcp_sport
          send_ack [:syn]
        elsif @state == SYN_SENT_STATE
          #debugger "======#{@self_seq_no.to_s 16}"
          @self_seq_no += 1
          #debugger "======#{@self_seq_no.to_s 16}"
          debugger "======#{@last_sent_ack_no.to_s 16}"
          @state = ESTABLISHED_STATE
          send_ack
        end

      elsif tcp_flags.fin == 1
        if @state == ESTABLISHED_STATE
          @state = LAST_ACK_STATE
          send_ack [:fin]
        elsif @state == FIN_WAIT_1_STATE
          if tcp_flags.ack == 1
            @state = FIN_WAIT_2_STATE
          end

          @self_seq_no += 1
          send_ack
          @state = TIME_WAIT_STATE
          # wait for 2 Max Segment Life time
          close
          exit
        elsif @state == FIN_WAIT_2_STATE
          @self_seq_no = packet.tcp_ack + 1
          send_ack
          @state = TIME_WAIT_STATE
          # wait for 2 Max Segment Life time
          close
        end

      elsif tcp_flags.ack == 1
        if @state == SYN_RECEIVED_STATE
          @state = ESTABLISHED_STATE
          @self_seq_no += 1
          @send_state = READY_STATE
        elsif @state == ESTABLISHED_STATE
          if packet.payload.size > 0
            @receiver_buffer += packet.payload
            send_ack
          end

          @send_state = READY_STATE
        elsif @state == FIN_WAIT_1_STATE
          @state = FIN_WAIT_2_STATE
        elsif @state == LAST_ACK_STATE
          close
          exit
        end

      else
        raise "#{__method__}: Don't know how to deal with the packet"
      end
    rescue Exception => e
      debugger "#{__method__}: Exception: #{e.message}"
      debugger "#{__method__}: #{e.backtrace.join "\n"}"
    end
  end

  def send_text payload
    while @state != ESTABLISHED_STATE and @send_state != READY_STATE
      sleep 0.001
    end

    send_ack [:psh], payload
    @send_state = BLOCKING_STATE
  end

  def listen port
    @src_port = port

    # listen
    @state = LISTEN_STATE
    Thread.new {self.listener}

    # debug
    Thread.new {self.state_watcher}
    puts "Listening on port #{port}..."

    previous_receiver_buffer = ''

    while true
      if previous_receiver_buffer != @receiver_buffer
        previous_receiver_buffer = @receiver_buffer
        yield previous_receiver_buffer
      end
    end
  end

  def open_url url, ip = nil
    uri = URI url
    host = uri.host
    ip ||= Resolv.getaddress host
    port = 80

    debugger "#{__method__}: host: #{host}, IP: #{ip}, port: #{port}, path: #{uri.path}"

    connect "#{ip}:#{port}" do
      payload = "GET #{uri.path} HTTP/1.0\r\nHost: #{host}\r\n\r\n"

      send_ack [:psh], payload

      while @state != CLOSED_STATE
        sleep 0.001
      end

      yield @receiver_buffer
    end
  end

  def listener
    filter = if @role == :client
               #"tcp and dst #{@src_ip} dst port #{@src_port} and src #{@dst_ip} and src port #{@dst_port}"
               "tcp and dst #{@src_ip} and dst port #{@src_port} and src #{@dst_ip} and src port #{@dst_port}"
             else
               "tcp and dst port #{@src_port}"
             end

    debugger "#{__method__}: Start listening with filter #{filter}"

    PacketFu::Capture.new(
      iface: @config[:iface],
      start: true,
      filter: filter
    ).stream.each do |stream|
      packet = PacketFu::Packet.parse(stream)

      #debugger "#{__method__}: Got packet #{packet.inspect}"

      state = self.handle packet

      if state == CLOSED_STATE
        return
      end
    end
  end

  private

  def debugger msg
    puts msg if @debug
  end

  def state_watcher
    debugger "#{__method__}: State is #{@state}"
    previous_state = @state

    while @state != CLOSED_STATE
      if @state != previous_state
        debugger "#{__method__}: State is #{@state}"
        previous_state = @state
      end
    end

    exit
  end

  def get_seq_no packet
    tcp_flags = packet.tcp_flags

    if [ESTABLISHED_STATE, FIN_WAIT_1_STATE, FIN_WAIT_2_STATE, TIME_WAIT_STATE, CLOSE_WAIT_STATE, LAST_ACK_STATE].include?(@state) and packet.payload.size > 0
      packet.tcp_seq + packet.payload.size
    elsif (tcp_flags.syn == 1) or (tcp_flags.fin == 1)
      packet.tcp_seq + 1
    else
      packet.tcp_seq
    end
  end

  def generate_seq_no
    Random.rand 100000
  end
end
