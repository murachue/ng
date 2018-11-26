# coding: utf-8

require "csv"

def main fn
	entries = []
	CSV.open(fn, "r") { |f|
		f.gets # skip header
		while not f.eof
			city_native,city,lat,lng,country,cc2,cc3,pref,capital,population,id = f.gets
			capital != "" and population != "" and entries << [city,country,lng,lat,population.to_i.to_s,capital == "primary" ? "1" : "0"]
		end
	}
	entries.sort_by!{|ci,co,*others| [co, ci]}
	widths = [0] * entries[0].size
	entries.each { |e| widths = widths.zip(e).map { |w,ec| [w, ec.size].max } }
	widths = widths[0..-2].map{|e| e + 2 } + [widths[-1]]
	entries.each { |e|
		e.zip(widths).each { |ec, w|
			print ec.ljust(w, " ")
		}
		puts
	}
end

$0 == __FILE__ and main *ARGV
