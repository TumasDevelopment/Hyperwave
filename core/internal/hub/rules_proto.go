package hub

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Regole sui protocolli applicativi riconosciuti dal sensore (tabella sessions).

func protoCatalog() []*RuleDef {
	return []*RuleDef{
		{
			ID: "weak_auth", Name: "Protocollo o autenticazione debole", Category: "Configurazione", Severity: "medium", Mitre: "T1557",
			Description: "SMBv1, NTLMv1, RDP senza NLA, server SSH con algoritmi rotti, ticket Kerberos RC4 o account senza preautenticazione.",
			Params:      params{"protocols": "ssh,rdp,smb,ntlm,kerberos"},
			Help:        map[string]string{"protocols": "Protocolli da controllare"},
			Every:       5, Window: 5 * time.Minute, Run: ruleWeakAuth,
		},
		{
			ID: "kerberoast", Name: "Kerberoasting", Category: "Accesso", Severity: "high", Mitre: "T1558.003",
			Description: "Un host chiede in poco tempo ticket RC4 per molti servizi diversi: i ticket si possono attaccare offline per ricavare le password degli account di servizio.",
			Params:      params{"min_services": 3},
			Help:        map[string]string{"min_services": "Servizi diversi con ticket RC4 in 15 minuti"},
			Every:       5, Window: 15 * time.Minute, Run: ruleKerberoast,
		},
		{
			ID: "kerberos_fail", Name: "Password errate su Kerberos", Category: "Accesso", Severity: "high", Mitre: "T1110.003",
			Description: "Molti tentativi Kerberos falliti da uno stesso host, o tentativi su molti utenti diversi (password spraying).",
			Params:      params{"min_failures": 10, "min_users": 5},
			Help:        map[string]string{"min_failures": "Tentativi falliti in 10 minuti", "min_users": "Utenti diversi provati in 10 minuti"},
			Every:       5, Window: 10 * time.Minute, Run: ruleKerberosFail,
		},
	}
}

var protoLabels = map[string]string{"ssh": "SSH", "rdp": "RDP", "smb": "SMB", "ntlm": "NTLM", "kerberos": "Kerberos", "http": "HTTP"}

func ruleWeakAuth(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Server, Protocol, Weak, Client, Since string
		Users                                 []string
		Port                                  uint16
		Clients                               uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT server AS Server, protocol AS Protocol, weak AS Weak, any(client) AS Client, any(port) AS Port,
		       uniqExact(client) AS Clients, groupUniqArrayIf(10)(user, user != '') AS Users, toString(min(ts)) AS Since
		FROM sessions WHERE `+inWindow+` AND weak != '' AND protocol IN {p:Array(String)}
		GROUP BY server, protocol, weak LIMIT 200`,
		w.params(map[string]string{"p": chStrings(p.list("protocols"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		srv := label(r.Server, e.h.enr.device(r.Server).name)
		proto := firstNonEmpty(protoLabels[r.Protocol], r.Protocol)
		sum := fmt.Sprintf("%s su %s (porta %d): %s. Visto con %d client", proto, srv, r.Port, r.Weak, r.Clients)
		if len(r.Users) > 0 {
			sum += ", utenti: " + strings.Join(r.Users, ", ")
		}
		out = append(out, Alert{
			DedupKey: "weak_auth|" + r.Server + "|" + r.Protocol + "|" + r.Weak, Src: r.Client, Dst: r.Server, TS: parseCH(r.Since),
			Title: fmt.Sprintf("%s debole su %s", proto, srv), Summary: sum + ".",
			Detail: map[string]any{"protocol": r.Protocol, "weak": r.Weak, "port": r.Port, "users": r.Users, "clients": r.Clients},
		})
	}
	return out, nil
}

func ruleKerberoast(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Client, User, Since string
		Services            uint64
		List                []string
	}
	rows, err := q[row](ctx, e, `
		SELECT client AS Client, any(user) AS User, uniqExact(host) AS Services, groupUniqArray(10)(host) AS List, toString(min(ts)) AS Since
		FROM sessions WHERE `+inWindow+` AND protocol = 'kerberos' AND startsWith(weak, 'ticket cifrato')
		      AND host != '' AND NOT startsWith(host, 'krbtgt/')
		GROUP BY client HAVING Services >= {min:UInt32} LIMIT 200`,
		w.params(map[string]string{"min": chInt(p.num("min_services"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Client, e.h.enr.device(r.Client).name)
		out = append(out, Alert{
			DedupKey: "kerberoast|" + r.Client, Src: r.Client, TS: parseCH(r.Since),
			Title: "Possibile Kerberoasting da " + who,
			Summary: fmt.Sprintf("%s (utente %s) ha chiesto ticket RC4 per %d servizi diversi tra le %s e le %s: %s.",
				who, firstNonEmpty(r.User, "sconosciuto"), r.Services, e.clock(w.from), e.clock(w.to), strings.Join(r.List, ", ")),
			Detail: map[string]any{"user": r.User, "services": r.List},
		})
	}
	return out, nil
}

func ruleKerberosFail(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Client, Server, Domain, Since string
		Fails, Users                  uint64
		List                          []string
	}
	rows, err := q[row](ctx, e, `
		SELECT client AS Client, any(server) AS Server, any(domain) AS Domain, count() AS Fails, uniqExact(user) AS Users,
		       groupUniqArray(10)(user) AS List, toString(min(ts)) AS Since
		FROM sessions WHERE `+inWindow+` AND protocol = 'kerberos'
		      AND (position(info, 'KDC_ERR_PREAUTH_FAILED') > 0 OR position(info, 'KDC_ERR_C_PRINCIPAL_UNKNOWN') > 0)
		GROUP BY client HAVING Fails >= {fails:UInt32} OR Users >= {users:UInt32} LIMIT 200`,
		w.params(map[string]string{"fails": chInt(p.num("min_failures")), "users": chInt(p.num("min_users"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Client, e.h.enr.device(r.Client).name)
		title, sev := "Password errate su Kerberos da "+who, ""
		if r.Users >= uint64(p.num("min_users")) {
			title = "Password spraying su Kerberos da " + who
			sev = "critical"
		}
		out = append(out, Alert{
			DedupKey: "kerberos_fail|" + r.Client, Severity: sev, Src: r.Client, Dst: r.Server, TS: parseCH(r.Since),
			Title: title,
			Summary: fmt.Sprintf("%s ha fallito %d autenticazioni Kerberos su %d utenti del dominio %s tra le %s e le %s (es. %s).",
				who, r.Fails, r.Users, firstNonEmpty(r.Domain, "?"), e.clock(w.from), e.clock(w.to), strings.Join(r.List, ", ")),
			Detail: map[string]any{"failures": r.Fails, "users": r.List, "domain": r.Domain},
		})
	}
	return out, nil
}
