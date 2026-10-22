package configsecret

import "go.dedis.ch/kyber/v4/share"

func recoverBusiness(m Manifest, e Envelope, parts map[string]Partial, binding string) ([]byte, error) {
	verified := []*share.PubShare{}
	defer func() {
		for _, p := range verified {
			p.V.Null()
		}
	}()
	for i, node := range m.Nodes {
		p, ok := parts[node.ID]
		if !ok || p.Index != uint32(i) {
			continue
		}
		v, err := verifyPartial(m, e, p, binding+"/"+node.ID)
		if err == nil {
			verified = append(verified, v)
		}
	}
	return combine(m, e, verified)
}
