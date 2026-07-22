package mixtransport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	ReferenceSlotInterval   = 5 * time.Second
	ReferencePollEverySlots = 6
)

var (
	ErrPacketProviderRequired = errors.New("audited post-quantum hybrid mix packet provider required")
	ErrPrivateLinkRequired    = errors.New("audited post-quantum fixed-frame entry link required")
	ErrQueueFull              = errors.New("ENIG-Mix outbound queue is full")
	ErrCommandExpired         = errors.New("ENIG-Mix command expired before dispatch")
	ErrScheduleDiscontinuity  = errors.New("ENIG-Mix constant-rate schedule was interrupted")
)

type Config struct {
	PacketBytes    int
	SlotInterval   time.Duration
	PollEverySlots uint64
	MaxQueue       int
	MaxLateness    time.Duration
	DispatchBudget time.Duration
}

type DispatchResult struct {
	RequestID string
	SentAt    time.Time
	Err       error
}

type Ticket struct {
	result <-chan DispatchResult
}

func (ticket Ticket) Wait(ctx context.Context) (DispatchResult, error) {
	if ticket.result == nil {
		return DispatchResult{}, errors.New("invalid ENIG-Mix dispatch ticket")
	}
	select {
	case result := <-ticket.result:
		return result, result.Err
	case <-ctx.Done():
		return DispatchResult{}, ctx.Err()
	}
}

type queuedPacket struct {
	requestID string
	expiresAt time.Time
	packet    []byte
	result    chan DispatchResult
}

type Scheduler struct {
	config   Config
	provider PacketProvider
	sink     PacketSink

	mu           sync.Mutex
	queue        []*queuedPacket
	reservations int
	slots        uint64
	running      bool
	terminalErr  error
}

func NewScheduler(config Config, provider PacketProvider, sink PacketSink) (*Scheduler, error) {
	if config.PacketBytes == 0 {
		config.PacketBytes = DefaultPacketBytes
	}
	if config.SlotInterval == 0 {
		config.SlotInterval = ReferenceSlotInterval
	}
	if config.PollEverySlots == 0 {
		config.PollEverySlots = ReferencePollEverySlots
	}
	if config.MaxQueue == 0 {
		config.MaxQueue = 1024
	}
	if config.MaxLateness == 0 {
		config.MaxLateness = config.SlotInterval / 4
	}
	if config.DispatchBudget == 0 {
		config.DispatchBudget = config.SlotInterval / 2
	}
	if config.PacketBytes != DefaultPacketBytes || config.SlotInterval != ReferenceSlotInterval ||
		config.PollEverySlots != ReferencePollEverySlots ||
		config.MaxQueue <= 0 || config.MaxQueue > MaxQueueEntries ||
		config.MaxLateness <= 0 || config.MaxLateness >= config.SlotInterval ||
		config.DispatchBudget <= 0 || config.DispatchBudget >= config.SlotInterval {
		return nil, errors.New("invalid ENIG-Mix scheduler configuration")
	}
	if provider == nil || !validPacketSecurity(provider.Security()) {
		return nil, ErrPacketProviderRequired
	}
	if sink == nil || !validLinkSecurity(sink.Security()) {
		return nil, ErrPrivateLinkRequired
	}
	return &Scheduler{config: config, provider: provider, sink: sink}, nil
}

func validPacketSecurity(security PacketSecurity) bool {
	return security.Protocol != "" && security.IndependentAudit != "" && security.MinimumMixHops >= 3 &&
		security.FixedLengthPackets && security.LayeredMixing && security.PerHopAuthentication &&
		security.ReplayProtection && security.UniformReplies && security.PostQuantumHybridOnion &&
		security.ForwardSecureRoutingKeys
}

func validLinkSecurity(security LinkSecurity) bool {
	return security.Protocol != "" && security.IndependentAudit != "" && security.AuthenticatedEntry &&
		security.PersistentConnection && security.FixedLengthFrames && security.PostQuantumHybridKEX &&
		security.NoRedirects
}

// Enqueue performs all variable application work away from the scheduled send
// instant. Queue capacity is reserved before provider work or allocation.
func (scheduler *Scheduler) Enqueue(ctx context.Context, command Command, now time.Time) (Ticket, error) {
	if scheduler == nil || scheduler.provider == nil {
		return Ticket{}, errors.New("ENIG-Mix scheduler is unavailable")
	}
	if err := ValidateCommand(command, now); err != nil {
		return Ticket{}, err
	}
	scheduler.mu.Lock()
	if scheduler.terminalErr != nil {
		err := scheduler.terminalErr
		scheduler.mu.Unlock()
		return Ticket{}, err
	}
	if len(scheduler.queue)+scheduler.reservations >= scheduler.config.MaxQueue {
		scheduler.mu.Unlock()
		return Ticket{}, ErrQueueFull
	}
	scheduler.reservations++
	scheduler.mu.Unlock()

	reserved := true
	defer func() {
		if reserved {
			scheduler.mu.Lock()
			scheduler.reservations--
			scheduler.mu.Unlock()
		}
	}()
	encoded, err := EncodeCommand(command, now)
	if err != nil {
		return Ticket{}, err
	}
	defer zero(encoded)
	prepared, err := scheduler.provider.PrepareReal(ctx, encoded, scheduler.config.PacketBytes)
	if err != nil {
		return Ticket{}, err
	}
	if err := scheduler.validatePrepared(prepared); err != nil {
		return Ticket{}, err
	}
	result := make(chan DispatchResult, 1)
	queued := &queuedPacket{
		requestID: command.RequestID,
		expiresAt: command.ExpiresAt,
		packet:    append([]byte(nil), prepared.Packet...),
		result:    result,
	}
	scheduler.mu.Lock()
	scheduler.reservations--
	reserved = false
	if scheduler.terminalErr != nil {
		err := scheduler.terminalErr
		scheduler.mu.Unlock()
		zero(queued.packet)
		return Ticket{}, err
	}
	scheduler.queue = append(scheduler.queue, queued)
	scheduler.mu.Unlock()
	return Ticket{result: result}, nil
}

func (scheduler *Scheduler) validatePrepared(prepared PreparedPacket) error {
	if len(prepared.Packet) != scheduler.config.PacketBytes {
		return errors.New("mix packet provider returned an invalid fixed-size packet")
	}
	return nil
}

// Run is the production timing loop. Any missed slot or transport failure ends
// the run, because continuing would make the advertised traffic shape false.
func (scheduler *Scheduler) Run(ctx context.Context) (runErr error) {
	if scheduler == nil {
		return errors.New("ENIG-Mix scheduler is unavailable")
	}
	scheduler.mu.Lock()
	if scheduler.running || scheduler.terminalErr != nil {
		scheduler.mu.Unlock()
		return errors.New("ENIG-Mix scheduler cannot be started more than once")
	}
	scheduler.running = true
	scheduler.mu.Unlock()
	defer func() {
		if runErr == nil {
			runErr = ErrScheduleDiscontinuity
		}
		scheduler.mu.Lock()
		scheduler.running = false
		scheduler.terminalErr = runErr
		scheduler.mu.Unlock()
		scheduler.failQueued(runErr)
	}()

	next := time.Now().Add(scheduler.config.SlotInterval)
	timer := time.NewTimer(time.Until(next))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			now := time.Now()
			if now.Sub(next) > scheduler.config.MaxLateness {
				return ErrScheduleDiscontinuity
			}
			if err := scheduler.dispatchSlot(ctx, now); err != nil {
				return err
			}
			next = next.Add(scheduler.config.SlotInterval)
			until := time.Until(next)
			if until <= 0 {
				return ErrScheduleDiscontinuity
			}
			timer.Reset(until)
		}
	}
}

func (scheduler *Scheduler) dispatchSlot(ctx context.Context, now time.Time) error {
	started := time.Now()
	dispatchCtx, cancel := context.WithTimeout(ctx, scheduler.config.DispatchBudget)
	defer cancel()
	cover, err := scheduler.provider.PrepareCover(dispatchCtx, scheduler.config.PacketBytes)
	if err != nil {
		return fmt.Errorf("prepare mandatory cover packet: %w", err)
	}
	if err := scheduler.validatePrepared(cover); err != nil {
		return err
	}
	defer zero(cover.Packet)

	scheduler.mu.Lock()
	scheduler.slots++
	pollSlot := scheduler.slots%scheduler.config.PollEverySlots == 0
	var queued *queuedPacket
	if !pollSlot && len(scheduler.queue) > 0 {
		candidate := scheduler.queue[0]
		scheduler.queue = scheduler.queue[1:]
		if now.After(candidate.expiresAt) {
			zero(candidate.packet)
			candidate.result <- DispatchResult{RequestID: candidate.requestID, Err: ErrCommandExpired}
		} else {
			queued = candidate
		}
	}
	scheduler.mu.Unlock()

	packet := cover.Packet
	var poll PreparedPacket
	if pollSlot {
		poll, err = scheduler.provider.PreparePoll(dispatchCtx, scheduler.config.PacketBytes)
		if err != nil {
			return fmt.Errorf("prepare mandatory anonymous poll: %w", err)
		}
		if err := scheduler.validatePrepared(poll); err != nil {
			return err
		}
		defer zero(poll.Packet)
		packet = poll.Packet
	} else if queued != nil {
		packet = queued.packet
		defer zero(queued.packet)
	}

	err = scheduler.sink.Send(dispatchCtx, packet)
	if err == nil && time.Since(started) > scheduler.config.DispatchBudget {
		err = ErrScheduleDiscontinuity
	}
	if queued != nil {
		queued.result <- DispatchResult{RequestID: queued.requestID, SentAt: now.UTC(), Err: err}
	}
	if err != nil {
		return fmt.Errorf("send fixed ENIG-Mix slot: %w", err)
	}
	return nil
}

func (scheduler *Scheduler) failQueued(runErr error) {
	if runErr == nil {
		runErr = ErrScheduleDiscontinuity
	}
	scheduler.mu.Lock()
	queued := scheduler.queue
	scheduler.queue = nil
	scheduler.mu.Unlock()
	for _, packet := range queued {
		zero(packet.packet)
		packet.result <- DispatchResult{RequestID: packet.requestID, Err: runErr}
	}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
