./bind.sh $1
../build/app/testpmd -c 0x3 -n 4 --vdev 'eth_af_xdp,iface='$1'' -- -i --mbuf-size=1856 --mp-flags=65
./unbind.sh $1
