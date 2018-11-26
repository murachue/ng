# coding: utf-8

module ExIO
	def readld; read(4).unpack("V")[0]; end
	def readbd; read(4).unpack("N")[0]; end
	def readlf; read(8).unpack("d")[0]; end
end

def main fn
	open(fn, "rb") { |f|
		f.extend ExIO
		# https://en.wikipedia.org/wiki/Shapefile
		f.readbd == 0x270a or raise "?magic"
		5.times { f.readbd }
		f.readbd # file-length including header
		f.readld # version
		[3, 5].include? f.readld or raise "?file-shapetype"
		file_mbr = 4.times.map { f.readlf }
		zrange = 2.times.map { f.readlf }
		mrange = 2.times.map { f.readlf }

		# TODO limit by file-length
		xr = [0, 0]
		yr = [0, 0]
		while not f.eof
			pos = f.pos
			begin
				recno = f.readbd
				reclen = f.readbd * 2   # in "words" to bytes...
				4 <= reclen or raise "?shortest-record"
				rectype = f.readld
				rectype == 0 and next   # skip null-shape
				[3, 5].include? rectype or raise "?record-shapetype (#{recno})"
				(4 + 8*4 + 4 + 4) <= reclen or raise "?record-too-short"
				rec_mbr = 4.times.map { f.readlf }
				nparts = f.readld
				npoints = f.readld
				expectlen = (4 + 8*4 + 4 + 4 + 4*nparts + 8*2*npoints)
				expectlen == reclen or raise "?record-size-mismatch (expects #{expectlen} but actual #{reclen})"
				parts = nparts.times.map { f.readld }
				npoints.times { |i|
					if parts[0] == i
						puts "b"
						parts.shift
					end
					x = f.readlf
					y = f.readlf
					xr = [[xr[0], x].min, [xr[1], x].max]
					yr = [[yr[0], y].min, [yr[1], y].max]
					# enable following lines if shape is mercator projection, or do not if WGS84 projection.
					#unit_deg = 1.0/20000000
					#x *= unit_deg * 180
					#y *= unit_deg * 90
					puts "%.6f %.6f" % [x, y] # -180..180 -90..90
				}
			rescue
				$stderr.puts "at file position %xh" % pos
				raise
			end
		end
		$stderr.puts [xr, yr].inspect
	}
end

$0 == __FILE__ and main *ARGV
