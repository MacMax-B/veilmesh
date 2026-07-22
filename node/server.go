package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"veilmesh/nodedir"
	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

const (
	receiptDomain       = "storage-receipt"
	proofDomain         = "storage-proof"
	deleteReceiptDomain = "delete-receipt"
)

type Server struct {
	config   Config
	store    *DiskStore
	signer   *pqcrypto.HybridSigner
	identity protocol.NodePublicIdentity
	mux      *http.ServeMux

	directory       *nodedir.Agent
	directoryWork   chan struct{}
	directoryRateMu sync.Mutex
	directoryLast   map[string]time.Time
	requestWork     chan struct{}
}

func NewServer(config Config, store *DiskStore, signer *pqcrypto.HybridSigner) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if store == nil || signer == nil {
		return nil, errors.New("node store and signer are required")
	}
	s := &Server{
		config:      config,
		store:       store,
		signer:      signer,
		identity:    signer.PublicIdentity(),
		mux:         http.NewServeMux(),
		requestWork: make(chan struct{}, config.MaxConcurrentRequests),
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(s.limitConcurrentRequests(s.mux))
}

func (s *Server) limitConcurrentRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.requestWork <- struct{}{}:
			defer func() { <-s.requestWork }()
			next.ServeHTTP(w, r)
		default:
			writeError(w, http.StatusServiceUnavailable, errors.New("node request capacity reached"))
		}
	})
}

// EnableDirectory installs the signed node-directory endpoints. It must be
// called during startup, before Handler is served.
func (s *Server) EnableDirectory(agent *nodedir.Agent) error {
	if agent == nil || agent.IdentityID() != s.identity.NodeID {
		return errors.New("node directory agent identity does not match server")
	}
	if s.directory != nil {
		return errors.New("node directory is already enabled")
	}
	s.directory = agent
	s.directoryWork = make(chan struct{}, 8)
	s.directoryLast = make(map[string]time.Time)
	s.mux.HandleFunc("GET /v1/nodes", s.handleNodeDirectory)
	s.mux.HandleFunc("POST /v1/nodes/register", s.handleNodeRegistration)
	s.mux.HandleFunc("POST /v1/nodes/challenge", s.handleNodeChallenge)
	return nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /v1/identity", s.handleIdentity)
	s.mux.HandleFunc("GET /v1/parameters", s.handleParameters)
	s.mux.HandleFunc("POST /v1/items", s.handleStore)
	s.mux.HandleFunc("POST /v1/fetch", s.handleFetch)
	s.mux.HandleFunc("POST /v1/proof", s.handleProof)
	s.mux.HandleFunc("POST /v1/delete", s.handleDelete)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) parameters() protocol.NodeParameters {
	used := s.store.Used()
	return protocol.NodeParameters{
		ProtocolVersion: protocol.ProtocolVersion,
		Difficulty:      s.config.EffectiveDifficulty(used),
		EpochSeconds:    s.config.EpochSeconds,
		MaxItemBytes:    s.config.MaxItemBytes,
		StorageUsed:     used,
		StorageCapacity: s.config.StorageCapacity,
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().UTC()})
}

func (s *Server) handleIdentity(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.identity)
}

func (s *Server) handleParameters(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.parameters())
}

func (s *Server) handleNodeDirectory(w http.ResponseWriter, r *http.Request) {
	remoteIP, err := requestIP(r)
	if err != nil || !s.acquireDirectoryWork(remoteIP, time.Now(), false) {
		writeError(w, http.StatusTooManyRequests, errors.New("directory request rate exceeded"))
		return
	}
	defer s.releaseDirectoryWork()
	snapshot, err := s.directory.Snapshot(time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleNodeRegistration(w http.ResponseWriter, r *http.Request) {
	remoteIP, err := requestIP(r)
	if err != nil || !s.acquireDirectoryWork(remoteIP, time.Now(), true) {
		writeError(w, http.StatusTooManyRequests, errors.New("directory request rate exceeded"))
		return
	}
	defer s.releaseDirectoryWork()
	var request nodedir.RegistrationRequest
	if err := decodeJSON(w, r, &request, nodedir.MaxRegistrationBytes); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	probeContext, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	record, err := s.directory.AcceptRegistration(probeContext, remoteIP, request, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) handleNodeChallenge(w http.ResponseWriter, r *http.Request) {
	remoteIP, err := requestIP(r)
	if err != nil || !s.acquireDirectoryWork(remoteIP, time.Now(), true) {
		writeError(w, http.StatusTooManyRequests, errors.New("directory request rate exceeded"))
		return
	}
	defer s.releaseDirectoryWork()
	var request nodedir.ChallengeRequest
	if err := decodeJSON(w, r, &request, 8*1024); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	response, err := s.directory.Challenge(request.Nonce, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func requestIP(request *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, errors.New("invalid remote address")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, errors.New("invalid remote IP")
	}
	return address.Unmap(), nil
}

func (s *Server) acquireDirectoryWork(remoteIP netip.Addr, now time.Time, rateLimit bool) bool {
	if s.directoryWork == nil || !remoteIP.IsValid() {
		return false
	}
	if rateLimit {
		key := remoteIP.String()
		s.directoryRateMu.Lock()
		if previous, exists := s.directoryLast[key]; exists && now.Sub(previous) < time.Second {
			s.directoryRateMu.Unlock()
			return false
		}
		if len(s.directoryLast) >= 4096 {
			cutoff := now.Add(-10 * time.Minute)
			for address, seenAt := range s.directoryLast {
				if seenAt.Before(cutoff) {
					delete(s.directoryLast, address)
				}
			}
			if len(s.directoryLast) >= 4096 {
				s.directoryRateMu.Unlock()
				return false
			}
		}
		s.directoryLast[key] = now
		s.directoryRateMu.Unlock()
	}
	select {
	case s.directoryWork <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseDirectoryWork() { <-s.directoryWork }

func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	var item protocol.StoredItem
	if err := decodeJSON(w, r, &item, int64(s.config.MaxItemBytes*2+64*1024)); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := protocol.ValidateItem(item, now, s.config.MaxItemBytes); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	parameters := s.parameters()
	if err := protocol.VerifyWork(item, now, parameters.EpochSeconds, parameters.Difficulty); err != nil {
		writeError(w, http.StatusTooManyRequests, err)
		return
	}
	if err := s.store.Put(item); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrMailboxQuota) || errors.Is(err, ErrStorageFull) {
			status = http.StatusInsufficientStorage
		}
		writeError(w, status, err)
		return
	}
	payloadHash := sha256.Sum256(item.Payload)
	receipt := protocol.StorageReceipt{
		NodeID:      s.identity.NodeID,
		ItemID:      item.ItemID,
		PayloadHash: payloadHash[:],
		StoredAt:    now,
		ExpiresAt:   item.ExpiresAt,
	}
	signature, err := s.signer.Sign(receiptDomain, protocol.ReceiptSigningBytes(receipt))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	receipt.Signature = signature
	writeJSON(w, http.StatusCreated, receipt)
}

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	var request protocol.FetchRequest
	if err := decodeJSON(w, r, &request, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(request.RouteTags) == 0 || len(request.RouteTags) > protocol.MaxRouteTagsPerFetch {
		writeError(w, http.StatusBadRequest, errors.New("route tag count out of range"))
		return
	}
	seen := make(map[string]struct{}, len(request.RouteTags))
	for _, routeTag := range request.RouteTags {
		if !protocol.ValidRouteTag(routeTag) {
			writeError(w, http.StatusBadRequest, errors.New("invalid route tag"))
			return
		}
		if _, duplicate := seen[routeTag]; duplicate {
			writeError(w, http.StatusBadRequest, errors.New("duplicate route tag"))
			return
		}
		seen[routeTag] = struct{}{}
	}
	items, truncated := s.store.FetchLimited(request.RouteTags, s.config.MaxFetchItems, s.config.MaxFetchBytes)
	if truncated {
		writeError(w, http.StatusRequestEntityTooLarge, errors.New("fetch result exceeds response limits"))
		return
	}
	writeJSON(w, http.StatusOK, protocol.FetchResponse{Items: items})
}

func (s *Server) handleProof(w http.ResponseWriter, r *http.Request) {
	var request protocol.ProofRequest
	if err := decodeJSON(w, r, &request, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !validItemID(request.ItemID) || len(request.Nonce) < 16 || len(request.Nonce) > 64 ||
		request.Length <= 0 || request.Length > protocol.MaxProofSampleBytes || request.Offset < 0 {
		writeError(w, http.StatusBadRequest, errors.New("invalid proof challenge"))
		return
	}
	item, err := s.store.Get(request.ItemID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if request.Offset > int64(len(item.Payload))-int64(request.Length) {
		writeError(w, http.StatusBadRequest, errors.New("proof offset outside payload"))
		return
	}
	end := request.Offset + int64(request.Length)
	payloadHash := sha256.Sum256(item.Payload)
	proof := protocol.StorageProof{
		NodeID:      s.identity.NodeID,
		ItemID:      item.ItemID,
		Nonce:       append([]byte(nil), request.Nonce...),
		Offset:      request.Offset,
		Sample:      append([]byte(nil), item.Payload[request.Offset:end]...),
		PayloadHash: payloadHash[:],
		ProvedAt:    time.Now().UTC().Truncate(time.Millisecond),
	}
	proof.Signature, err = s.signer.Sign(proofDomain, protocol.ProofSigningBytes(proof))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, proof)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	var request protocol.DeleteRequest
	if err := decodeJSON(w, r, &request, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !validItemID(request.ItemID) || len(request.DeleteToken) != protocol.CapabilityBytes {
		writeError(w, http.StatusBadRequest, errors.New("invalid delete request"))
		return
	}
	item, err := s.store.Get(request.ItemID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !pqcrypto.DeleteTokenMatches(item.DeleteTokenHash, request.DeleteToken) {
		// Make a wrong capability indistinguishable from an unknown item.
		writeError(w, http.StatusNotFound, ErrNotFound)
		return
	}
	if err := s.store.Delete(item.ItemID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	receipt := protocol.DeleteReceipt{
		NodeID:    s.identity.NodeID,
		ItemID:    item.ItemID,
		DeletedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
	receipt.Signature, err = s.signer.Sign(deleteReceiptDomain, protocol.DeleteReceiptSigningBytes(receipt))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any, limit int64) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	message := "request failed"
	if status < http.StatusInternalServerError && err != nil {
		message = err.Error()
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func RandomChallenge() ([]byte, error) {
	value := make([]byte, 32)
	_, err := rand.Read(value)
	return value, err
}
