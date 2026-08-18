// The secrets ops (../soul-hq/02-DESIGN/soulstream-identity/tenancy.md
// D36): the custodian's general secret store on the principal-scoped
// surface. The persona in every op is the server-proven caller —
// reachability is the deployment's permission template on the op tail
// (D25), so the only tree a caller can ever touch is its own; the
// service makes zero identity decisions. Values ride the sealed
// envelope (D16) and never appear in any log line.

package service

import (
	"encoding/base64"
	"errors"
	"fmt"
)

type secretPutRequest struct {
	Path string `json:"path"`
	// Value is base64; the envelope seals it in transit, the store at rest.
	Value string `json:"value"`
	// ExpectedRev conditions the write (D2): 0 creates, >0 updates iff
	// the stored revision matches.
	ExpectedRev uint64 `json:"expected_rev,omitempty"`
}

type secretPutResponse struct {
	Rev uint64 `json:"rev"`
}

type secretGetRequest struct {
	Path string `json:"path"`
}

type secretGetResponse struct {
	Value string `json:"value"`
	Rev   uint64 `json:"rev"`
}

type secretsListResponse struct {
	Paths []string `json:"paths"`
}

type secretDeleteRequest struct {
	Path string `json:"path"`
}

func (s *Service) requireSecrets() error {
	if s.secrets == nil {
		return errors.New("service: this deployment runs no secret store")
	}
	return nil
}

func (s *Service) dispatchSecrets(account, user, op string, body []byte) (any, error) {
	if err := s.requireSecrets(); err != nil {
		return nil, err
	}
	switch op {
	case "secrets.put":
		var req secretPutRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		value, err := base64.StdEncoding.DecodeString(req.Value)
		if err != nil {
			return nil, fmt.Errorf("service: secret value is not base64: %w", err)
		}
		rev, err := s.secrets.Put(user, req.Path, value, req.ExpectedRev)
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op, "path", req.Path, "rev", rev)
		return secretPutResponse{Rev: rev}, nil

	case "secrets.get":
		var req secretGetRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		value, rev, err := s.secrets.Get(user, req.Path)
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op, "path", req.Path)
		return secretGetResponse{Value: base64.StdEncoding.EncodeToString(value), Rev: rev}, nil

	case "secrets.list":
		paths, err := s.secrets.List(user)
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op)
		return secretsListResponse{Paths: paths}, nil

	case "secrets.delete":
		var req secretDeleteRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		if err := s.secrets.Delete(user, req.Path); err != nil {
			return nil, err
		}
		s.allow(account, user, op, "path", req.Path)
		return struct{}{}, nil

	default:
		return nil, fmt.Errorf("service: unknown op %q", op)
	}
}
