// Code generated by tools/cmd/genjwa/main.go. DO NOT EDIT.

package jwa

import (
	"fmt"
	"sort"
	"sync"
)

// EllipticCurveAlgorithm represents the algorithms used for EC keys
type EllipticCurveAlgorithm string

// Supported values for EllipticCurveAlgorithm
const (
	Ed25519              EllipticCurveAlgorithm = "Ed25519"
	Ed448                EllipticCurveAlgorithm = "Ed448"
	InvalidEllipticCurve EllipticCurveAlgorithm = "P-invalid"
	P256                 EllipticCurveAlgorithm = "P-256"
	P384                 EllipticCurveAlgorithm = "P-384"
	P521                 EllipticCurveAlgorithm = "P-521"
	X25519               EllipticCurveAlgorithm = "X25519"
	X448                 EllipticCurveAlgorithm = "X448"
)

var allEllipticCurveAlgorithms = map[EllipticCurveAlgorithm]struct{}{
	Ed25519: {},
	Ed448:   {},
	P256:    {},
	P384:    {},
	P521:    {},
	X25519:  {},
	X448:    {},
}

var listEllipticCurveAlgorithmOnce sync.Once
var listEllipticCurveAlgorithm []EllipticCurveAlgorithm

// EllipticCurveAlgorithms returns a list of all available values for EllipticCurveAlgorithm
func EllipticCurveAlgorithms() []EllipticCurveAlgorithm {
	listEllipticCurveAlgorithmOnce.Do(func() {
		listEllipticCurveAlgorithm = make([]EllipticCurveAlgorithm, 0, len(allEllipticCurveAlgorithms))
		for v := range allEllipticCurveAlgorithms {
			listEllipticCurveAlgorithm = append(listEllipticCurveAlgorithm, v)
		}
		sort.Slice(listEllipticCurveAlgorithm, func(i, j int) bool {
			return string(listEllipticCurveAlgorithm[i]) < string(listEllipticCurveAlgorithm[j])
		})
	})
	return listEllipticCurveAlgorithm
}

// Accept is used when conversion from values given by
// outside sources (such as JSON payloads) is required
func (v *EllipticCurveAlgorithm) Accept(value interface{}) error {
	var tmp EllipticCurveAlgorithm
	if x, ok := value.(EllipticCurveAlgorithm); ok {
		tmp = x
	} else {
		var s string
		switch x := value.(type) {
		case fmt.Stringer:
			s = x.String()
		case string:
			s = x
		default:
			return fmt.Errorf(`invalid type for jwa.EllipticCurveAlgorithm: %T`, value)
		}
		tmp = EllipticCurveAlgorithm(s)
	}
	if _, ok := allEllipticCurveAlgorithms[tmp]; !ok {
		return fmt.Errorf(`invalid jwa.EllipticCurveAlgorithm value`)
	}

	*v = tmp
	return nil
}

// String returns the string representation of a EllipticCurveAlgorithm
func (v EllipticCurveAlgorithm) String() string {
	return string(v)
}