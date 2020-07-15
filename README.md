mdns-scan is a tool for scanning for mDNS/DNS-SD published services on the
local network. It issues a mDNS PTR query to the special RR
_services._dns-sd._udp.local for retrieving a list of all currently registered
services on the local link.

mdns-scan is not a good mDNS citizen since it queries continuously for services
and doesn't implement features like Duplicate Suppression. It is intended for
usage as a debugging tool only.

mdns-scan is incomplete since it doesn't resolve mDNS services for you - it
just dumps their PTR RRs. To understand these records you need minimal
knowledge of DNS-SD and how it works.

mdns-scan does not terminate on its own behalf. It scans for services
continuously until the user kills it by pressing C-c.

mdns-scan does not rely on a local mDNS responder daemon. It has no
dependencies besides the GNU libc. It has been tested on Linux only.

mdns-scan does NOT scan for local mDNS enabled hosts or A/AAAA RRs, it scans
for DNS-SD registered services, nothing else.

Changes from 0.1 to 0.2:
  
  Send mDNS queries on all local interfaces that support it, not only on the
  default one.

Changes from 0.2 to 0.3:
  
  Add debian/ directory

Changes from 0.3 to 0.4:

  Add man pages
  Improvements to the Debianization

-- 
December 2004, Lennart Poettering, mzzqaffpna (at) 0pointer (dot) de
$Id: README 76 2005-01-23 15:22:47Z lennart $
