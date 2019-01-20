# ng: Network Graphicalizer

## How to build

First, prepare coastlines data from somewhere.

Option-A: get land\_polygon from OpenStreetMap data ( http://openstreetmapdata.com/data/land-polygons ),
simplify it, then place `land_polygon.shp`.

Option-B: pull coastlines.dat from DEFCON ( https://www.introversion.co.uk/defcon/ ) and place it into `data/` directory.

Option-C: make it yourself and place it into `data/` directory!

Option-D: `touch data/coastlines.dat`

Then,

```
$ make
```

And pray for succeed.
Online required because Makefile includes fetching data from the Internet.

## How to launch

```
# ./ng <interfacename> [bpf]
```

or

```
$ ./ng <pcapfilename> [bpf]
```

ex.

```
$ XAUTHORITY=$HOME/.Xauthority sudo ./ng enp0s3 not tcp port 22
```

```
$ ./ng foo.pcap
```

## How to operate

Arrow key: navigate nodes

ESC: navigate to null

i: show/hide node informations

colon: activate command line (ESC cancels)

### Command line

`help` helps you, but required to set `loglines` to enough.
(it says how to do it.)

`q` or `quit` closes this application.

The `autoexec` file is executed at launch time.

Do `source demoexec` for getting fun instantly.

Note: no history function yet... hitting arrow key in command line does not perform
any special things. It only navigate nodes.

## Data formats

### data/cities.dat

Tab-delimited text file.

```
<longitude> <latitude> <population> <capital?> <iso3166_1_alpha_2> <countryname>
...
```

note for country fields:
`iso3166_1_alpha_2` is used for ipaddress-to-contry key,
`countryname` is used just for display.

### data/coastlines.dat, data/international.dat

Text file consists from blocks of poly-lines.

poly-lines block is described as follows:

```
b
<longitude> <latitude>
<longitude> <latitude>
[<longitude> <latitude>]...
```

### data/iplist.dat

Tab-delimited text file.

```
<ipv4start> <numaddresses> <iso3166_1_alpha_2>
...
```

## Copyright and License

Copyright 2019 Murachue <murachue+github@gmail.com> and masawaki.

License: GPLv2

### traceroute-2.0.3 (part of)

Copyright (c) 2006 Dmitry K. Butskoy <buc@citadel.stu.neva.ru>

License: GPL (COPYING is GPLv2, no "and later" notation)

https://sourceforge.net/projects/traceroute/files/traceroute/traceroute-2.0.3/traceroute-2.0.3.tar.gz/download

### worldcities.csv

Copyright 2016 Pareto Software, LLC.

Licensed under Creative Commons Attribution 4.0.

https://simplemaps.com/data/world-cities

### note using OpenStreetMap data's land\_polygons for coastlines.dat

Since Open Database License (ODbL) is not compatible with GPL,
I cannot distribute it with this software.

See: https://www.gnu.org/licenses/license-list.html.en#ODbl

So, you must do manually fetch land\_polygons(.shp) and convert using
`shp2dat.rb` to load into this software, or use other "coast lines"
data.
