package report

type EventKind string

const (
	EventWrite   EventKind = "write"
	EventConnect EventKind = "connect"
)

type Decision string

const (
	DecisionAllowed    Decision = "allowed"
	DecisionWouldBlock Decision = "would_block"
)

type Event struct {
	Kind     EventKind `json:"kind"`
	Decision Decision  `json:"decision"`
	Target   string    `json:"target"`
}

type Summary struct {
	Total      int               `json:"total"`
	WouldBlock int               `json:"would_block"`
	ByKind     map[EventKind]int `json:"by_kind"`
}

type Recorder struct {
	events []Event
}

func New() *Recorder {
	return &Recorder{}
}

func (r *Recorder) Record(event Event) {
	r.events = append(r.events, event)
}

func (r *Recorder) Events() []Event {
	return append([]Event(nil), r.events...)
}

func (r *Recorder) Summary() Summary {
	s := Summary{ByKind: map[EventKind]int{}}
	for _, event := range r.events {
		s.Total++
		s.ByKind[event.Kind]++
		if event.Decision == DecisionWouldBlock {
			s.WouldBlock++
		}
	}
	return s
}
