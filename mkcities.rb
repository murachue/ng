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

# http://www.iso.org/iso/home/standards/country_codes/country_names_and_code_elements_txt.htm
isocc = {}
open("iplist/country_names_and_code_elements_txt.htm","r"){|f|f.gets;while s=f.gets;country,cc = s.chomp.split(";");isocc[country]=cc;end}

output = ""
open("cities.dat", "r") do |f|
	while s = f.gets
		s.chomp!
		city, country, x, y, popul, ismetro = s.split("\t")
		cc = ccmap[country.upcase] || country # convert from old-name to new-name
		cc = isocc[cc.upcase] || cc # convert from long-name to two-chars-name
		output += "#{x}\t#{y}\t#{popul}\t#{ismetro}\t#{cc}\t#{city}\n"
	end
end
# only when everything goes well, over-write out.
open("data/cities.dat", "w") { |g| g.write output }
