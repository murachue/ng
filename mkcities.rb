# coding: utf-8

# cities.dat country -> ISO3166 country
ccmap = {
"ANTIGUA & B" => "ANTIGUA AND BARBUDA",
"BOLIVIA" => "BOLIVIA, PLURINATIONAL STATE OF",
"BRUNEI DARUISSALAM" => "BRUNEI DARUSSALAM",
#"BURMA" => "",
"CAYMAN IS" => "CAYMAN ISLANDS",
#"CHANNEL ISLANDS" => "",
#"COTE D'LVOIRE" => "",
"CZECHOSLOVAKIA" => "CZECH REPUBLIC", # or SLOVAKIA
#"DEMOCRATIC KAMPUCHEA" => "",
"DEMOCRATIC YEMEN" => "YEMEN",
"DOMINICAN REP" => "DOMINICAN REPUBLIC",
"E. TIMOR" => "TIMOR-LESTE",
"FAEROE ISLANDS" => "FAROE ISLANDS",
"FALKLAND ISLANDS" => "FALKLAND ISLANDS (MALVINAS)",
"GERMAN DEMOCRATIC REPUBLIC" => "GERMANY", # ?
"HOLY SEE" => "HOLY SEE (VATICAN CITY STATE)",
"IRAN" => "IRAN, ISLAMIC REPUBLIC OF",
"KOREA" => "KOREA, REPUBLIC OF",
"LAO PEOPLE'S DEM. REP." => "LAO PEOPLE'S DEMOCRATIC REPUBLIC",
"LIBYAN ARAB" => "LIBYA",
"MACAU" => "MACAO",
"NETHS. ANTTILLES" => "NETHERLANDS", # ...
"NORTHERN IRELAND" => "IRELAND", # ?
"REUNION" => "FRANCE", # Saint-Denis Reunion
"S. AFRICA" => "SOUTH AFRICA",
"S.AFRICA" => "SOUTH AFRICA",
"SABAH" => "MALAYSIA", # ?
"SARAWAK" => "MALAYSIA", # ?
"SCOTLAND" => "UNITED KINGDOM", # ?
"ST. CHRISTOPHER AND NEVIS" => "SAINT KITTS AND NEVIS",
"ST. HELENA" => "SAINT HELENA, ASCENSION AND TRISTAN DA CUNHA",
"ST. LUCIA" => "SAINT LUCIA",
"ST. PIERRE AND MIQUELON" => "SAINT PIERRE AND MIQUELON",
"ST. VINCENT AND THE GRENADINES" => "SAINT VINCENT AND THE GRENADINES",
"TANZANIA" => "TANZANIA, UNITED REPUBLIC OF",
"USA" => "UNITED STATES",
"USAVIRGIN ISLANDS" => "VIRGIN ISLANDS, U.S.", # ?
"USSR" => "RUSSIAN FEDERATION",
"VENEZUELA" => "VENEZUELA, BOLIVARIAN REPUBLIC OF",
"VIRGIN IS." => "VIRGIN ISLANDS, BRITISH", # or US?
"W. SAHARA" => "WESTERN SAHARA",
"YUGOSLAVIA" => "MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF", # ?
"ZAIRE" => "CONGO, THE DEMOCRATIC REPUBLIC OF THE", # ?
}

# http://www.iso.org/iso/home/standards/country_codes/country_names_and_code_elements_txt.htm ...is dead at most 2018/11/25
# https://raw.githubusercontent.com/mrdragonraaar/CountryCodes/master/iso-3166/country_names_and_code_elements.txt
isocc = {}
open(ARGV[0],"r") { |f|
	f.gets
	begin
		while s = f.gets
			country, cc = s.chomp.split(";")
			isocc[country] = cc
		end
	rescue
		$stderr.puts "at countries line #{f.lineno}"
		raise
	end
}

output = ""
open(ARGV[1], "r") do |f|
	begin
		while s = f.gets
			s.chomp!
			city, country, x, y, popul, ismetro = s.split(/[\t ]{2,}/)
			cc = ccmap[country.upcase] || country   # convert from old-name to new-name
			cc = isocc[cc.upcase] || cc   # convert from long-name to two-chars-name
			puts [x, y, popul, ismetro, cc, city].join("\t")
		end
	rescue
		$stderr.puts "at cities line #{f.lineno}"
		raise
	end
end
