import configuration


configuration.getInstance().setFilePath('/home/bastian/Desktop/ardukey-auth-server.conf')

print(configuration.getInstance().exists('server_address'))

print(configuration.getInstance().getList('server_address'))

configuration.getInstance().setList('server_address', ['a'])

configuration.getInstance().set('bla', '1', section='JO')

print(configuration.getInstance().getList('server_address'))

configuration.getInstance().saveFile()
