// Package classify riconosce l'applicazione di un flusso dalla porta e dal dominio.
package classify

import "strings"

var tcpPorts = map[uint16]string{
	20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 88: "Kerberos",
	110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
	465: "SMTPS", 554: "RTSP", 587: "SMTP", 636: "LDAPS", 853: "DNS su TLS", 993: "IMAPS", 995: "POP3S",
	1433: "MS SQL", 1883: "MQTT", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5061: "SIP TLS",
	5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis", 8080: "HTTP",
	8443: "HTTPS", 8883: "MQTT TLS", 9100: "Stampa", 873: "rsync", 2049: "NFS", 3260: "iSCSI",
}

var udpPorts = map[uint16]string{
	53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
	161: "SNMP", 162: "SNMP", 443: "QUIC", 500: "IPsec", 514: "Syslog", 1194: "OpenVPN", 1900: "SSDP",
	3478: "STUN", 4500: "IPsec", 5060: "SIP", 5353: "mDNS", 5355: "LLMNR", 8801: "Zoom", 51820: "WireGuard",
}

// ByPort restituisce l'applicazione più probabile per la porta del server.
func ByPort(proto string, port uint16) string {
	switch proto {
	case "TCP":
		if a, ok := tcpPorts[port]; ok {
			return a
		}
	case "UDP":
		if a, ok := udpPorts[port]; ok {
			return a
		}
		if port >= 10000 && port <= 20000 {
			return "RTP"
		}
	case "ICMP", "ICMPv6":
		return proto
	}
	return ""
}

// Coppie suffisso del dominio → applicazione. L'ordine conta: i più specifici prima.
var domains = []struct{ suffix, app string }{
	{"teams.microsoft.com", "Microsoft Teams"}, {"teams.live.com", "Microsoft Teams"},
	{"windowsupdate.com", "Windows Update"}, {"update.microsoft.com", "Windows Update"},
	{"sharepoint.com", "Microsoft 365"}, {"office.com", "Microsoft 365"}, {"office365.com", "Microsoft 365"},
	{"office.net", "Microsoft 365"}, {"outlook.com", "Microsoft 365"}, {"live.com", "Microsoft 365"},
	{"microsoft.com", "Microsoft"}, {"msftconnecttest.com", "Microsoft"}, {"azure.com", "Azure"},
	{"youtube.com", "YouTube"}, {"googlevideo.com", "YouTube"}, {"ytimg.com", "YouTube"},
	{"google.com", "Google"}, {"gstatic.com", "Google"}, {"googleapis.com", "Google"}, {"google.it", "Google"},
	{"zoom.us", "Zoom"}, {"whatsapp.net", "WhatsApp"}, {"whatsapp.com", "WhatsApp"},
	{"facebook.com", "Facebook"}, {"fbcdn.net", "Facebook"}, {"instagram.com", "Instagram"},
	{"netflix.com", "Netflix"}, {"nflxvideo.net", "Netflix"}, {"github.com", "GitHub"},
	{"githubusercontent.com", "GitHub"}, {"amazonaws.com", "AWS"}, {"cloudflare.com", "Cloudflare"},
	{"icloud.com", "Apple"}, {"apple.com", "Apple"}, {"dropbox.com", "Dropbox"}, {"slack.com", "Slack"},
	{"anydesk.com", "AnyDesk"}, {"teamviewer.com", "TeamViewer"}, {"spotify.com", "Spotify"},
	{"tiktok.com", "TikTok"}, {"tiktokcdn.com", "TikTok"}, {"linkedin.com", "LinkedIn"},
	{"salesforce.com", "Salesforce"}, {"mega.nz", "MEGA"}, {"wetransfer.com", "WeTransfer"},
	{"torproject.org", "Tor"}, {"ntp.org", "NTP"}, {"ubuntu.com", "Ubuntu"}, {"debian.org", "Debian"},
}

// generiche: quando il dominio è noto, l'applicazione per dominio vince.
var generic = map[string]bool{"": true, "HTTPS": true, "HTTP": true, "TLS": true, "QUIC": true, "STUN": true, "RTP": true, "Zoom": true}

// Refine sostituisce un'applicazione generica con quella ricavata dal dominio.
func Refine(app, domain string) string {
	if domain == "" || !generic[app] {
		return app
	}
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, e := range domains {
		if d == e.suffix || strings.HasSuffix(d, "."+e.suffix) {
			return e.app
		}
	}
	return app
}
