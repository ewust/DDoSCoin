# style from http://youinfinitesnake.blogspot.com/2011/02/attractive-scientific-plots-with.html

set terminal pdfcairo font "Gill Sans,12" linewidth 4 rounded

set style line 80 lt rgb "#808080"

set style line 81 lt 0  # dashed
set style line 81 lt rgb "#808080"  # grey

set grid back linestyle 81
set border 3 back linestyle 80 # Remove border on top and right.  These
             # borders are useless and make it harder
             # to see plotted lines near the border.
    # Also, put it in grey; no need for so much emphasis on a border.
set xtics nomirror
set ytics nomirror

set style line 1 lt rgb "#A00000" lw 2 pt 1
set style line 2 lt rgb "#00A000" lw 2 pt 6
set style line 3 lt rgb "#5060D0" lw 2 pt 2
set style line 4 lt rgb "#F25900" lw 2 pt 9


set output 'times.pdf'


set style data boxplot
#set boxwidth 0.5 absolute
#set style fill   solid 0.25 border lt -1
#unset key
#set style data boxplot
#set xtics border in scale 0,0 nomirror norotate  autojustify
#set xtics  norangelimit
#set xtics   ("A" 1.00000, "B" 2.00000)
#set ytics border in scale 1,0.5 nomirror norotate  autojustify
set yrange [ 0.00000 : 1.000 ] noreverse nowriteback
#set xrange [ 0:30 ]
set logscale x
## Last datafile plotted: "silver.dat"
set xlabel 'Time (ms)'
set ylabel 'CDF'

plot 'normal.data.cdf' using 1:2 with lines lw 2 title 'Normal', \
    'ddos.data.cdf' using 1:2 with lines lw 2 title 'Under DDoS'

