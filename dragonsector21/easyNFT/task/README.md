One of our servers is acting strangely lately.
There are even rumours that it gives out flags if [asked in a right way](https://xkcd.com/424/).

Our forensic team didn't find any backdoors, but when we try to list firewall rules, `nft` just hangs.
The best we could get is this the netlink dump attached in easynft.pcap.

Could you help us figure out what's going on?

P.S. Obviously, the flag was redacted from the dump.


easynft.hackable.software 34.159.43.116


tshark -r task/easynft.pcap -x | grep -v "0000" | awk -F "  " '{print $2}' | tr -d ' ' > hex.dump   