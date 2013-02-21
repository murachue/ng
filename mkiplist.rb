#!/usr/bin/env ruby

ARGV.each do |fn|
	open(fn, "r") do |f|
		f.gets # skip first
		while s = f.gets
			flds = s.split("|")
			if flds[2] == "ipv4" and flds[3] != "*"
				puts "#{flds[3]}\t#{flds[4]}\t#{flds[1]}"
			end
		end
	end
end
