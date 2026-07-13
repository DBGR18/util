// Package ngap: NGAP message metrics, built against the new
// github.com/free5gc/ngap API (ie package).
package ngap

import (
	ngapie "github.com/free5gc/ngap/ie"
)

func GetCauseErrorStr(cause *ngapie.Cause) string {
	if cause != nil && cause.Choice != nil {
		return cause.String()
	}

	return UNKNOWN_NGAP_TYPE_CAUSE_ERR
}
