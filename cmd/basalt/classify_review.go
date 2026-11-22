package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/pii/classify"
)

// The terminal review of basalt classify is layout C, "summary first, then
// only what needs you" (owner decision OR-4): a summary line of counts, then
// per table the columns grouped by class with SECRET first and the reason as
// names and counts, the needs-review columns last, each asked about on its
// own before the table's question.

// narrowTerminal is the width below which the reason moves to a second,
// indented line instead of wrapping.
const narrowTerminal = 100

// reviewClasses is the order classes are listed in, the most protective
// first.
var reviewClasses = []string{guard.ClassSecret, guard.ClassIdentifier, guard.ClassFreeText, guard.ClassPublic, guard.ClassUnclassified}

const (
	classColumn  = 12 // width of the class label column
	reasonIndent = "      "
	reviewMark   = "⚠"
)

// printReview prints the summary and every table.
func (r classifyRun) printReview(w io.Writer, width int) {
	if !printSummary(w, r.tables) {
		return
	}
	for _, t := range r.tables {
		printTable(w, t, width)
	}
}

// printSummary prints the count line; false when nothing is shown.
func printSummary(w io.Writer, tables []classify.ReviewTable) bool {
	counts := map[string]int{}
	total, review := 0, 0
	for _, t := range tables {
		for _, c := range t.Columns {
			counts[c.Suggestion.Class]++
			total++
			if c.Suggestion.NeedsReview {
				review++
			}
		}
	}
	if total == 0 {
		fmt.Fprintln(w, "Nothing to classify: every column the agents can read has a class (basalt classify --review=all shows them).")
		return false
	}
	fmt.Fprintf(w, "%d columns to classify in %d tables\n", total, len(tables))
	parts := make([]string, 0, len(reviewClasses)+1)
	for _, class := range reviewClasses {
		if counts[class] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", class, counts[class]))
		}
	}
	parts = append(parts, fmt.Sprintf("%s needs review %d", reviewMark, review))
	fmt.Fprintln(w, strings.Join(parts, "  "))
	return true
}

// printTable prints one table: settled suggestions by class, then the
// needs-review columns.
func printTable(w io.Writer, t classify.ReviewTable, width int) {
	fmt.Fprintf(w, "\n%s\n", visibleText(t.Table))
	nameWidth, entityWidth := 0, 0
	for _, c := range t.Columns {
		nameWidth = max(nameWidth, len(visibleText(c.Column.Name)))
		entityWidth = max(entityWidth, len(entityLabel(c)))
	}
	narrow := width > 0 && width < narrowTerminal
	for _, class := range reviewClasses {
		label := class
		for _, c := range t.Columns {
			if c.Suggestion.Class != class || c.Suggestion.NeedsReview {
				continue
			}
			line := fmt.Sprintf("  %-*s %-*s  %-*s", classColumn, label, nameWidth, visibleText(c.Column.Name), entityWidth, entityLabel(c))
			printWithReason(w, line, reasonText(c), narrow)
			label = ""
		}
	}
	for _, c := range t.Columns {
		if !c.Suggestion.NeedsReview {
			continue
		}
		line := fmt.Sprintf("  %s %s → %s?", reviewMark, visibleText(c.Column.Name), suggestionLabel(c.Suggestion))
		printWithReason(w, line, reasonText(c), narrow)
	}
}

func printWithReason(w io.Writer, line, reason string, narrow bool) {
	reason = visibleText(reason)
	if narrow {
		fmt.Fprintf(w, "%s\n%s%s\n", strings.TrimRight(line, " "), reasonIndent, reason)
		return
	}
	fmt.Fprintf(w, "%s  %s\n", line, reason)
}

// entityLabel is the entity type in its CLI spelling, with the phone region.
func entityLabel(c classify.ReviewColumn) string {
	s := c.Suggestion
	if s.EntityType == "" {
		return ""
	}
	label := spellEntity(s.EntityType)
	if s.EntityType == guard.EntityPhone && s.PhoneRegion != "" {
		label += " · " + s.PhoneRegion
	}
	return label
}

func suggestionLabel(s classify.Suggestion) string {
	if s.EntityType == "" {
		return s.Class
	}
	return s.Class + " " + spellEntity(s.EntityType)
}

// reasonText is the suggestion's reason, after what changed for a column
// that has a class already.
func reasonText(c classify.ReviewColumn) string {
	var notes []string
	if c.Status == classify.StatusTypeChanged {
		notes = append(notes, "type changed from "+c.Stored.DataType)
	}
	if c.Confirmed() && (c.Stored.Class != c.Suggestion.Class || c.Stored.EntityType != c.Suggestion.EntityType) {
		now := c.Stored.Class
		if c.Stored.EntityType != "" {
			now += " " + spellEntity(c.Stored.EntityType)
		}
		notes = append(notes, "now "+now)
	}
	return strings.Join(append(notes, c.Suggestion.Reason), "; ")
}

// errCanceled is returned when stdin ends before the review does.
var errCanceled = errors.New("classify canceled before the review ended; nothing written")

// ask runs the terminal review: the summary, then per table its columns,
// a question per needs-review column, and Accept the rest [Y/e/s].
func (r classifyRun) ask(c *cliIO, decided map[string]classify.Decision) error {
	if !printSummary(c.stdout, r.tables) {
		return nil
	}
	for _, t := range r.tables {
		printTable(c.stdout, t, c.width())
		if err := askTable(c, t, decided); err != nil {
			return err
		}
	}
	return nil
}

func askTable(c *cliIO, t classify.ReviewTable, decided map[string]classify.Decision) error {
	var rest []classify.ReviewColumn
	for _, col := range t.Columns {
		if !col.Suggestion.NeedsReview {
			rest = append(rest, col)
			continue
		}
		if err := askNeedsReview(c, col, decided); err != nil {
			return err
		}
	}
	if len(rest) == 0 {
		return nil
	}
	for {
		fmt.Fprintf(c.stderr, "Accept the rest for %s? [Y/e/s] ", visibleText(t.Table))
		answer, err := c.line()
		if err != nil {
			return errCanceled
		}
		switch strings.ToLower(answer) {
		case "", "y", "yes":
			for _, col := range rest {
				if _, ok := decided[col.Column.FullName()]; !ok {
					decided[col.Column.FullName()] = col.Suggested()
				}
			}
			return nil
		case "s", "skip":
			fmt.Fprintf(c.stderr, "basalt: skipped %s; its columns without a class stay UNCLASSIFIED\n", visibleText(t.Table))
			return nil
		case "e", "edit":
			if err := askEdit(c, t, decided); err != nil {
				return err
			}
		default:
			fmt.Fprintln(c.stderr, "basalt: answer y (accept), e (edit one column) or s (skip the table)")
		}
	}
}

// askNeedsReview asks about one needs-review column: yes keeps the
// protected suggestion; no asks for the class.
func askNeedsReview(c *cliIO, col classify.ReviewColumn, decided map[string]classify.Decision) error {
	fmt.Fprintf(c.stderr, "Protect %s as %s? [Y/n] ", visibleText(col.Column.Name), col.Suggestion.Class)
	answer, err := c.line()
	if err != nil {
		return errCanceled
	}
	if answer == "" || strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
		decided[col.Column.FullName()] = col.Suggested()
		return nil
	}
	for {
		fmt.Fprintf(c.stderr, "Class for %s (class[:entity-type]; empty leaves it UNCLASSIFIED): ", visibleText(col.Column.Name))
		answer, err := c.line()
		if err != nil {
			return errCanceled
		}
		if answer == "" {
			return nil
		}
		class, entity, err := parseClass(answer)
		if err != nil {
			fmt.Fprintf(c.stderr, "basalt: %v\n", err)
			continue
		}
		decided[col.Column.FullName()] = decisionFor(col, class, entity)
		return nil
	}
}

// askEdit reads one column=class[:entity-type] for the table.
func askEdit(c *cliIO, t classify.ReviewTable, decided map[string]classify.Decision) error {
	fmt.Fprint(c.stderr, "Edit (column=class[:entity-type]): ")
	answer, err := c.line()
	if err != nil {
		return errCanceled
	}
	name, spelled, ok := strings.Cut(answer, "=")
	if !ok {
		fmt.Fprintln(c.stderr, "basalt: write column=class[:entity-type], for example email=identifier:email")
		return nil
	}
	class, entity, err := parseClass(spelled)
	if err != nil {
		fmt.Fprintf(c.stderr, "basalt: %v\n", err)
		return nil
	}
	for _, col := range t.Columns {
		if col.Column.Name == strings.TrimSpace(name) {
			decided[col.Column.FullName()] = decisionFor(col, class, entity)
			fmt.Fprintf(c.stderr, "basalt: %s set to %s\n", visibleText(col.Column.Name), suggestionLabel(classify.Suggestion{Class: class, EntityType: entity}))
			return nil
		}
	}
	fmt.Fprintf(c.stderr, "basalt: %s has no column %s in this review\n", visibleText(t.Table), visibleText(strings.TrimSpace(name)))
	return nil
}

// decisionFor is a class a person typed for col, with the column's phone
// region when it is a phone.
func decisionFor(col classify.ReviewColumn, class, entity string) classify.Decision {
	d := classify.Decision{Class: class, EntityType: entity}
	if entity == guard.EntityPhone {
		d.PhoneRegion = col.Suggestion.PhoneRegion
		if d.PhoneRegion == "" && col.Stored != nil {
			d.PhoneRegion = col.Stored.PhoneRegion
		}
	}
	return d
}
