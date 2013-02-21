
# if you don't know how to build, type following text and hit enter:
#   make fetch data all

CFLAGS=
# for Mac:
#CFLAGS=-I/usr/X11R6/include -L/usr/X11R6/lib -DBSD
FETCH=wget

all: ng

clean:
	-rm ng tags

ng: ng.c
	gcc -g -Wall ng.c -pthread -lX11 -lpcap -lm -o ng $(CFLAGS)

tags: ng.c
	ctags ng.c

fetch:
	-[ -d iplist ] || mkdir iplist
	cd iplist; $(FETCH) ftp://ftp.arin.net/pub/stats/arin/delegated-arin-latest
	cd iplist; $(FETCH) ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest
	cd iplist; $(FETCH) ftp://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
	cd iplist; $(FETCH) ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-latest
	cd iplist; $(FETCH) ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest
	cd iplist; $(FETCH) http://www.iso.org/iso/home/standards/country_codes/country_names_and_code_elements_txt.htm

data:
	-[ -d data ] || mkdir data
	ruby mkiplist.rb iplist/delegated-*-latest > data/iplist.dat
	mv coastlines.dat data/
	mv international.dat data/
	ruby mkcities.rb
