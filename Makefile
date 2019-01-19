CFLAGS=-g
#CFLAGS=-O2
# for Mac:
#CFLAGS=-I/usr/X11R6/include -L/usr/X11R6/lib -DBSD
#FETCH=curl -LO
FETCH=wget

all: ng prepdata

clean:
	-rm ng tags data/iplist.dat data/coastlines.dat data/international.dat data/cities.dat

ng: ng.c
	gcc -Wall -o ng $(CFLAGS) $< -pthread -lX11 -lpcap -lm

tags: ng.c
	ctags ng.c

.PHONY: fetch
fetch: \
	iplist/delegated-arin-extended-latest \
	iplist/delegated-lacnic-latest \
	iplist/delegated-apnic-latest \
	iplist/delegated-ripencc-latest \
	iplist/delegated-afrinic-latest \
	iplist/country_names_and_code_elements.txt

# note: ARIN: non-extended file is deprecated and no more exists as of 2018/11/25.
#             extended format just adds a column at last, so compatible with mkiplist.rb.
iplist/delegated-arin-extended-latest:
	[ -d iplist ] || mkdir iplist
	cd iplist && $(FETCH) ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
iplist/delegated-lacnic-latest:
	[ -d iplist ] || mkdir iplist
	cd iplist && $(FETCH) ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest
iplist/delegated-apnic-latest:
	[ -d iplist ] || mkdir iplist
	cd iplist && $(FETCH) ftp://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
iplist/delegated-ripencc-latest:
	[ -d iplist ] || mkdir iplist
	cd iplist && $(FETCH) ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-latest
iplist/delegated-afrinic-latest:
	[ -d iplist ] || mkdir iplist
	cd iplist && $(FETCH) ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest
iplist/country_names_and_code_elements.txt:
	[ -d iplist ] || mkdir iplist
	cd iplist && $(FETCH) https://raw.githubusercontent.com/mrdragonraaar/CountryCodes/master/iso-3166/country_names_and_code_elements.txt

.PHONY: prepdata
prepdata: data/iplist.dat data/coastlines.dat data/international.dat data/cities.dat

data/iplist.dat: iplist/delegated-arin-extended-latest iplist/delegated-lacnic-latest iplist/delegated-apnic-latest iplist/delegated-ripencc-latest iplist/delegated-afrinic-latest
	[ -d data ] || mkdir data
	ruby mkiplist.rb iplist/delegated-*-latest > $@.tmp && mv $@.tmp $@
# note: land_polygons.shp from http://openstreetmapdata.com/data/land-polygons WGS84 projection,
#       simplified using "Visvalingam/effective area" by 0.01% at https://mapshaper.org/
#       Mercator projection shape can't be used because globe is sphere, not flat!!
data/coastlines.dat: land_polygons.shp
	[ -d data ] || mkdir data
	#cp coastlines.dat data/
	ruby shp2dat.rb $< > $@.tmp && mv $@.tmp $@
data/international.dat:
	[ -d data ] || mkdir data
	#cp international.dat data/
	touch $@
data/cities.dat: iplist/country_names_and_code_elements.txt cities.dat
	[ -d data ] || mkdir data
	ruby mkcities.rb $+ > $@.tmp && mv $@.tmp $@

# worldcities.csv from https://simplemaps.com/data/world-cities "Basic"
cities.dat: worldcities.csv
	ruby wcc2dat.rb $< > $@.tmp && mv $@.tmp $@
