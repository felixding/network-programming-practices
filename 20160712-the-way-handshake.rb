require 'packetfu'

CLOSED_STATE      = "CLOSED".freeze
SYN_SENT_STATE    = "SYN-SENT".freeze
ESTABLISHED_STATE = "ESTABLISHED".freeze
FIN_WAIT_1_STATE  = "FIN-WAIT-1".freeze
LAST_ACK_STATE    = "LAST-ACK".freeze

@config = PacketFu::Utils.whoami?

@to = :google
@to = :daike
@to = :dingyu

case @to
  when :daike
    @dst_ip = "121.199.36.74" # daike
    @dst_host = 'daike.dk'

  when :google
    @dst_ip = "172.217.4.78" # google
    @dst_host = 'www.google.com'

  when :dingyu
    @dst_ip = "104.236.219.141" # daike
    @dst_host = 'dingyu.me'
end

@dst_port = 80
@src_port = 10086

@buffer = ''

@client_next_seq = 0
@server_ack_seq = 0

@state = nil

def send_ack flags = [], payload = ''
  packet = PacketFu::TCPPacket.new(config: @config, flavor: "Mac")
  packet.ip_daddr = @dst_ip
  packet.tcp_dst = @dst_port
  packet.tcp_sport = @src_port
  packet.tcp_ack = @client_next_seq
  packet.tcp_seq = @server_ack_seq

  flags << :ack
  flags.each {|flag| packet.tcp_flags.send("#{flag}=".to_sym, 1) }

  puts "Send flags #{flags.collect{|flag| flag.upcase}.join(', ')}"

  if payload.size > 0
    packet.payload = payload
    puts "Send payload #{payload}"
  end

  packet.recalc
  packet.to_w

  @server_ack_seq += payload.size
end

def send_syn
  puts "Send SYN to #{@dst_ip}"
  packet = PacketFu::TCPPacket.new(config: @config, flavor: "Mac")
  packet.ip_daddr = @dst_ip
  packet.tcp_sport = @src_port
  packet.tcp_dst = @dst_port
  packet.tcp_flags.syn = 1
  packet.recalc
  packet.to_w
end

send_syn

@state = SYN_SENT_STATE

cap = PacketFu::Capture.new(
  iface: @config[:iface],
  start: true,
  filter: "tcp and src #{@dst_ip}"
)

cap.stream.each do |stream|
  packet = PacketFu::Packet.parse(stream)
  tcp_flags = packet.tcp_flags

  @client_next_seq = packet.tcp_seq + 1
  @server_ack_seq = packet.tcp_ack

  #puts packet.inspect
  puts "Got TCP FLAGS: #{tcp_flags.inspect}"

  if tcp_flags.rst == 1
    @state = CLOSED_STATE
    exit

  elsif tcp_flags.syn == 1
    if @state == SYN_SENT_STATE
      @state = ESTABLISHED_STATE
      send_ack [:psh], "GET / HTTP/1.0\r\nHost: #{@dst_host}\r\n\r\n"
    end

  elsif tcp_flags.fin == 1
    if @state == ESTABLISHED_STATE
      @state = LAST_ACK_STATE
      send_ack [:fin]
    end

  elsif tcp_flags.ack == 1
    if @state == LAST_ACK_STATE
      @state = CLOSED_STATE
      puts '----------CLOSED_STATE----------'
      puts @buffer
      exit
    elsif tcp_flags.syn == 0 and @state == SYN_SENT_STATE
      send_syn
    end

    if packet.payload.length > 0
      puts "Got payload: #{packet.payload.inspect}"
      @buffer += packet.payload
      send_ack
    end

  end

end
