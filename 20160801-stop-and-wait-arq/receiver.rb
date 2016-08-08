require './simple_tcp'

server = SimpleTCP.new :server
server.listen 10010 do |data|
  puts data
end
