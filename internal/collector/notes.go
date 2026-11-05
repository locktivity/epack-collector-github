package collector

import "github.com/locktivity/epack/componentsdk"

// runNotes collects the notes for the customer that no gap covers. Each
// becomes a run warning in the collector result that needs no action, and
// its message appears from the audit level. A value the run could not read
// needs no note, because its gap records the reason and what to do.
type runNotes struct {
	list []string
}

// featureOff adds a note for surface that a feature is turned off. The
// collector reports the setting as it finds it.
func (n *runNotes) featureOff(surface, what string) {
	n.list = append(n.list, "surface "+surface+": "+what)
}

// memberNamesIncomplete adds a note that display names are missing from some
// member rows for a reason other than the user not setting one, so consumers
// don't read an absent name as "not set".
func (n *runNotes) memberNamesIncomplete(reason string) {
	n.list = append(n.list, "members: display names incomplete: "+reason)
}

// note records message as a run warning that needs no action.
func (l *gapLog) note(message string) {
	l.rec.Warn(message, componentsdk.NoAction())
}
