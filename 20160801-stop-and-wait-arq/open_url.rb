require './simple_tcp'

# we need ip because Ruby's resolv does not work in China
sites = [
  {url: 'http://dingyu.me/', ip: '104.236.219.141'},
  {url: 'http://daike.dk/', ip: '121.199.36.74'}
]

site = sites[1]

client = SimpleTCP.new :client
client.open_url site[:url], site[:ip] do |data|
  puts data
end
