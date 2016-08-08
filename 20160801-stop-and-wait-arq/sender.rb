require './simple_tcp'

ip_and_port = ARGV[0] || '127.0.0.1:10010'
client = SimpleTCP.new :client
client.connect ip_and_port do
  client.send_text 'I finally made this work.'
  client.goodbye
end
