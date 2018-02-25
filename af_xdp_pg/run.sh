export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib64
../build/app/testpmd -c 0x3 -n 4 --vdev 'eth_af_xdp,iface='$1'' -- -i --mbuf-size=1856 --mp-flags=65 --eth-peer=0,08:00:27:31:24:36
