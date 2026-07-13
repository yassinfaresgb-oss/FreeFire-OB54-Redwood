# Server Addresses — Evidence

**Evidence for: FF-0001, FF-0005**

---

## Discovered Addresses

| Address | Protocol | Purpose | Source |
|---------|----------|---------|--------|
| `http://202.81.106.160:39001` | HTTP | MajorLogin fallback | VodkaConst.java:7 |
| `https://ffmconnect.live.gop.garenanow.com` | HTTPS | OAuth token endpoint | API code |
| `voice_service_address` | TCP | Voice signaling (dynamic) | MajorLogin response |

## Key Observations

1. **MajorLogin fallback uses HTTP** — `http://202.81.106.160:39001/MajorLogin`
2. **OAuth endpoint uses HTTPS** — standard practice
3. **Voice server address is dynamic** — provided by MajorLogin response
4. **IP address is hardcoded** — `202.81.106.160` is a direct IP, no DNS

---

*Evidence version: 2.0 · Last updated: July 2026*

---

*Author: swift.dev ([@yassinfaresgb-oss](https://github.com/yassinfaresgb-oss)) � Repository: [FreeFire-OB54-Redwood](https://github.com/yassinfaresgb-oss/FreeFire-OB54-Redwood)*
*Assessment conducted: July 2026 � Classification: Confidential � Internal Use Only*
