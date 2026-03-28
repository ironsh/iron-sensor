package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"iron-sensor/internal/classifier"
	"iron-sensor/internal/events"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// bpfEvent mirrors struct event in sensor.c.
type bpfEvent struct {
	Type    uint32
	PID     uint32
	PPID    uint32
	RootPID uint32
	ExitCode int32
	Comm    [16]byte
}

// bpfOpenEvent mirrors struct open_event in sensor.c.
type bpfOpenEvent struct {
	PID      uint32
	RootPID  uint32
	FD       int32
	Flags    int32
	Comm     [16]byte
	PathHint [256]byte
}

// bpfChmodEvent mirrors struct chmod_event in sensor.c.
type bpfChmodEvent struct {
	PID     uint32
	RootPID uint32
	Mode    uint32
	Comm    [16]byte
	Path    [256]byte
}

const (
	eventExec = 1
	eventExit = 2
)

type trackedAgent struct {
	signature string
	startTime time.Time
	comm      string
}

// Tracker loads BPF programs, runs bootstrap scan, and processes live events.
type Tracker struct {
	emitter    *events.Emitter
	classifier *classifier.Classifier

	objs  *sensorObjects
	links []link.Link

	signatures []Signature

	mu      sync.Mutex
	tracked map[uint32]*trackedAgent // agent_root_pid -> info
	comms   map[uint32]string        // pid -> comm for ppid lookups
}

func NewTracker(emitter *events.Emitter, cls *classifier.Classifier, sigs []Signature) *Tracker {
	return &Tracker{
		emitter:    emitter,
		classifier: cls,
		signatures: sigs,
		tracked:    make(map[uint32]*trackedAgent),
		comms:      make(map[uint32]string),
	}
}

// Load loads BPF programs and attaches tracepoints.
func (t *Tracker) Load() error {
	var objs sensorObjects
	if err := loadSensorObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	t.objs = &objs

	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TpSchedProcessFork, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("attaching fork tracepoint: %w", err)
	}

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TpSchedProcessExit, nil)
	if err != nil {
		tpFork.Close()
		objs.Close()
		return fmt.Errorf("attaching exit tracepoint: %w", err)
	}

	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.TpSchedProcessExec, nil)
	if err != nil {
		tpExit.Close()
		tpFork.Close()
		objs.Close()
		return fmt.Errorf("attaching exec tracepoint: %w", err)
	}

	tpOpenEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TpSysEnterOpenat, nil)
	if err != nil {
		tpExec.Close()
		tpExit.Close()
		tpFork.Close()
		objs.Close()
		return fmt.Errorf("attaching openat enter tracepoint: %w", err)
	}

	tpOpenExit, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TpSysExitOpenat, nil)
	if err != nil {
		tpOpenEnter.Close()
		tpExec.Close()
		tpExit.Close()
		tpFork.Close()
		objs.Close()
		return fmt.Errorf("attaching openat exit tracepoint: %w", err)
	}

	tpChmod, err := link.Tracepoint("syscalls", "sys_enter_fchmodat", objs.TpSysEnterFchmodat, nil)
	if err != nil {
		tpOpenExit.Close()
		tpOpenEnter.Close()
		tpExec.Close()
		tpExit.Close()
		tpFork.Close()
		objs.Close()
		return fmt.Errorf("attaching fchmodat tracepoint: %w", err)
	}

	t.links = []link.Link{tpFork, tpExit, tpExec, tpOpenEnter, tpOpenExit, tpChmod}
	return nil
}

// Bootstrap scans /proc for existing agent processes.
func (t *Tracker) Bootstrap() error {
	pids, err := scanProcs()
	if err != nil {
		return fmt.Errorf("scanning /proc: %w", err)
	}

	bootTime, err := readBootTime()
	if err != nil {
		log.Printf("warning: cannot read boot time: %v", err)
	}

	for _, pid := range pids {
		exe, err := readExe(pid)
		if err != nil {
			continue // process may have exited
		}
		argv, err := readCmdline(pid)
		if err != nil || len(argv) == 0 {
			continue
		}

		sig, ok := MatchWith(t.signatures, exe, argv)
		if !ok {
			continue
		}

		comm, _ := readComm(pid)

		// Approximate start time from /proc/<pid>/stat field 22.
		startTime := time.Now()
		if bootTime.Unix() > 0 {
			if ticks, err := readStartTimeTicks(pid); err == nil {
				startTime = bootTime.Add(time.Duration(ticks) * time.Second / 100)
			}
		}

		// Register in BPF map and Go-side tracking.
		t.registerAgent(pid, pid, sig, comm, startTime)

		ev := events.NewStartEvent(pid, pid, comm, exe, argv, sig, true)
		if err := t.emitter.Emit(ev); err != nil {
			log.Printf("error emitting bootstrap event for pid %d: %v", pid, err)
		}
		log.Printf("bootstrap: detected %s agent pid=%d", sig, pid)
	}
	return nil
}

// Run processes live BPF events until ctx is cancelled.
func (t *Tracker) Run(ctx context.Context) error {
	reader, err := perf.NewReader(t.objs.Events, os.Getpagesize()*64)
	if err != nil {
		return fmt.Errorf("creating perf reader: %w", err)
	}
	defer reader.Close()

	openReader, err := perf.NewReader(t.objs.OpenEvents, os.Getpagesize()*64)
	if err != nil {
		return fmt.Errorf("creating open perf reader: %w", err)
	}
	defer openReader.Close()

	chmodReader, err := perf.NewReader(t.objs.ChmodEvents, os.Getpagesize()*16)
	if err != nil {
		return fmt.Errorf("creating chmod perf reader: %w", err)
	}
	defer chmodReader.Close()

	go func() {
		<-ctx.Done()
		reader.Close()
		openReader.Close()
		chmodReader.Close()
	}()

	log.Println("live detection started")

	// Process open and chmod events in separate goroutines.
	go t.processOpenEvents(openReader)
	go t.processChmodEvents(chmodReader)

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			log.Printf("perf read error: %v", err)
			continue
		}

		if record.LostSamples > 0 {
			log.Printf("lost %d perf samples", record.LostSamples)
			continue
		}

		var ev bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("failed to parse event: %v", err)
			continue
		}

		switch ev.Type {
		case eventExec:
			t.handleExec(ev)
		case eventExit:
			t.handleExit(ev)
		}
	}
}

func (t *Tracker) processOpenEvents(reader *perf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("open perf read error: %v", err)
			continue
		}

		if record.LostSamples > 0 {
			log.Printf("lost %d open perf samples", record.LostSamples)
			continue
		}

		var oev bpfOpenEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &oev); err != nil {
			log.Printf("failed to parse open event: %v", err)
			continue
		}

		t.handleOpen(oev)
	}
}

func (t *Tracker) handleExec(ev bpfEvent) {
	pid := ev.PID
	rootPID := ev.RootPID
	comm := commString(ev.Comm)

	// Read process details from /proc. Process may have already exited.
	exe, _ := readExe(pid)
	argv, _ := readCmdline(pid)

	sig, isAgent := MatchWith(t.signatures, exe, argv)

	if isAgent {
		// If this pid was in a tracked subtree, promote it to the new root.
		if rootPID != 0 {
			t.mu.Lock()
			oldAgent := t.tracked[rootPID]
			t.mu.Unlock()

			if oldAgent != nil {
				t.promoteAgent(pid, rootPID, sig, comm, oldAgent.startTime)
				log.Printf("live: promoted %s agent pid=%d (was child of root %d)", sig, pid, rootPID)
				return
			}
		}

		// New agent, not in any tracked subtree.
		t.registerAgent(pid, pid, sig, comm, time.Now())

		startEv := events.NewStartEvent(pid, pid, comm, exe, argv, sig, false)
		if err := t.emitter.Emit(startEv); err != nil {
			log.Printf("error emitting start event for pid %d: %v", pid, err)
		}
		log.Printf("live: detected %s agent pid=%d", sig, pid)
		return
	}

	// Not an agent — emit a process event if this pid is in a tracked subtree.
	if rootPID == 0 {
		return
	}

	t.mu.Lock()
	_, tracked := t.tracked[rootPID]
	t.mu.Unlock()
	if !tracked {
		return
	}

	// Record comm for future ppid lookups by the classifier.
	t.recordComm(pid, comm)

	cwd := readCwd(pid)
	procEv := events.NewProcessEvent(pid, ev.PPID, rootPID, comm, exe, argv, cwd)
	if err := t.classifyAndEmit(procEv); err != nil {
		log.Printf("error emitting process event for pid %d: %v", pid, err)
	}
}

func (t *Tracker) handleExit(ev bpfEvent) {
	pid := ev.PID

	t.mu.Lock()
	agent, ok := t.tracked[pid]
	if ok {
		delete(t.tracked, pid)
	}
	t.mu.Unlock()

	if !ok {
		return // not a tracked agent root
	}

	duration := time.Since(agent.startTime).Milliseconds()
	stopEv := events.NewStopEvent(pid, pid, agent.signature, ev.ExitCode, duration)
	if err := t.emitter.Emit(stopEv); err != nil {
		log.Printf("error emitting stop event for pid %d: %v", pid, err)
	}
	log.Printf("live: %s agent pid=%d exited (code=%d, duration=%dms)", agent.signature, pid, ev.ExitCode, duration)
}

// promoteAgent transfers agent tracking from an old root to a new pid that
// exec'd into the agent binary (e.g., fork-then-exec pattern).
func (t *Tracker) promoteAgent(newPID, oldRootPID uint32, sig, comm string, startTime time.Time) {
	// Update BPF map: new pid becomes its own root.
	if t.objs != nil {
		if err := t.objs.PidToRoot.Put(newPID, newPID); err != nil {
			log.Printf("warning: failed to update BPF map for promoted pid %d: %v", newPID, err)
		}
	}

	t.mu.Lock()
	// Remove old root from tracking — its exit should not emit a stop event.
	delete(t.tracked, oldRootPID)
	// Track the new pid as the agent root.
	t.tracked[newPID] = &trackedAgent{
		signature: sig,
		startTime: startTime,
		comm:      comm,
	}
	t.mu.Unlock()
}

func (t *Tracker) registerAgent(pid, rootPID uint32, sig, comm string, startTime time.Time) {
	// Insert into BPF map for subtree tracking.
	if t.objs != nil {
		if err := t.objs.PidToRoot.Put(pid, rootPID); err != nil {
			log.Printf("warning: failed to update BPF map for pid %d: %v", pid, err)
		}
	}

	t.mu.Lock()
	t.tracked[rootPID] = &trackedAgent{
		signature: sig,
		startTime: startTime,
		comm:      comm,
	}
	t.mu.Unlock()

	// Scan existing children — they were forked before we added this pid to
	// the BPF map, so the fork tracepoint didn't propagate tracking. Add all
	// descendants to the map, and register any that match an agent signature.
	t.adoptSubtree(pid, rootPID, sig, startTime)
}

// adoptSubtree recursively adds all descendants of pid to the BPF map
// so the fork tracepoint propagates tracking for future children. Any
// descendant that matches an agent signature is registered as a tracked agent.
func (t *Tracker) adoptSubtree(pid, rootPID uint32, parentSig string, startTime time.Time) {
	children := readChildren(pid)
	for _, cpid := range children {
		// Add every child to BPF map for subtree tracking.
		if t.objs != nil {
			_ = t.objs.PidToRoot.Put(cpid, rootPID)
		}

		// Check if this child is itself an agent.
		exe, _ := readExe(cpid)
		argv, _ := readCmdline(cpid)
		if sig, ok := MatchWith(t.signatures, exe, argv); ok {
			t.mu.Lock()
			_, alreadyTracked := t.tracked[cpid]
			t.mu.Unlock()
			if !alreadyTracked {
				if t.objs != nil {
					_ = t.objs.PidToRoot.Put(cpid, cpid)
				}
				comm, _ := readComm(cpid)
				t.mu.Lock()
				t.tracked[cpid] = &trackedAgent{
					signature: sig,
					startTime: startTime,
					comm:      comm,
				}
				t.mu.Unlock()

				ev := events.NewStartEvent(cpid, cpid, comm, exe, argv, sig, false)
				if err := t.emitter.Emit(ev); err != nil {
					log.Printf("error emitting start event for adopted child pid %d: %v", cpid, err)
				}
				log.Printf("live: adopted %s agent child pid=%d (parent %d)", sig, cpid, pid)
				t.adoptSubtree(cpid, cpid, sig, startTime)
				continue
			}
		}

		// Recurse for non-agent children too — they may have agent descendants.
		t.adoptSubtree(cpid, rootPID, parentSig, startTime)
	}
}

func (t *Tracker) handleOpen(oev bpfOpenEvent) {
	pid := oev.PID
	rootPID := oev.RootPID

	// Verify the root is still tracked.
	t.mu.Lock()
	_, tracked := t.tracked[rootPID]
	t.mu.Unlock()
	if !tracked {
		return
	}

	pathHint := cString(oev.PathHint[:])
	flags := oev.Flags

	// Resolve full path via /proc/<pid>/fd/<fd> if fd is valid.
	path := pathHint
	if oev.FD >= 0 {
		if resolved := readFdPath(pid, oev.FD); resolved != "" {
			path = resolved
		}
	}

	// Apply filter: emit writes and sensitive reads.
	if !shouldEmitFileEvent(path, flags) {
		return
	}

	comm := commString(oev.Comm)
	exe, _ := readExe(pid)
	flagStr := FormatFlags(flags)

	fileEv := events.NewFileEvent(pid, rootPID, comm, exe, path, pathHint, flagStr)
	if err := t.classifyAndEmit(fileEv); err != nil {
		log.Printf("error emitting file event for pid %d: %v", pid, err)
	}
}

func (t *Tracker) processChmodEvents(reader *perf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("chmod perf read error: %v", err)
			continue
		}

		if record.LostSamples > 0 {
			log.Printf("lost %d chmod perf samples", record.LostSamples)
			continue
		}

		var cev bpfChmodEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &cev); err != nil {
			log.Printf("failed to parse chmod event: %v", err)
			continue
		}

		t.handleChmod(cev)
	}
}

func (t *Tracker) handleChmod(cev bpfChmodEvent) {
	pid := cev.PID
	rootPID := cev.RootPID

	t.mu.Lock()
	_, tracked := t.tracked[rootPID]
	t.mu.Unlock()
	if !tracked {
		return
	}

	comm := commString(cev.Comm)
	path := cString(cev.Path[:])

	ev := events.NewChmodEvent(pid, rootPID, comm, path, cev.Mode)
	if err := t.emitter.Emit(ev); err != nil {
		log.Printf("error emitting chmod event for pid %d: %v", pid, err)
	}
}

func (t *Tracker) classifyAndEmit(ev events.Event) error {
	ev = t.classifier.Classify(ev, t.lookupComm)
	return t.emitter.Emit(ev)
}

func (t *Tracker) lookupComm(pid uint32) string {
	t.mu.Lock()
	comm := t.comms[pid]
	t.mu.Unlock()
	if comm != "" {
		return comm
	}
	// Fall back to /proc if not cached.
	c, _ := readComm(pid)
	return c
}

func (t *Tracker) recordComm(pid uint32, comm string) {
	t.mu.Lock()
	t.comms[pid] = comm
	t.mu.Unlock()
}

func cString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		n = len(b)
	}
	return string(b[:n])
}

// Close detaches tracepoints and closes BPF objects.
func (t *Tracker) Close() error {
	for _, l := range t.links {
		l.Close()
	}
	if t.objs != nil {
		t.objs.Close()
	}
	return nil
}

func commString(comm [16]byte) string {
	n := bytes.IndexByte(comm[:], 0)
	if n < 0 {
		n = 16
	}
	return string(comm[:n])
}

// readBootTime reads /proc/stat to determine system boot time.
func readBootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("btime ")) {
			var btime int64
			if _, err := fmt.Sscanf(string(line), "btime %d", &btime); err != nil {
				return time.Time{}, err
			}
			return time.Unix(btime, 0), nil
		}
	}
	return time.Time{}, fmt.Errorf("btime not found in /proc/stat")
}
