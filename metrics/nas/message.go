// Package nas: NAS message metrics, built against the new
// github.com/free5gc/nas API (ie/message packages).
package nas

import (
	"regexp"

	"github.com/prometheus/client_golang/prometheus"

	nasie "github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/util/metrics/utils"
)

var suffixRe = regexp.MustCompile(`\s*\(\d+\)$`)

var (
	NasMsgRcvCounter  *prometheus.CounterVec
	NasMsgSentCounter *prometheus.CounterVec
)

func GetNasHandlerMetrics(namespace string) []prometheus.Collector {
	var collectors []prometheus.Collector

	NasMsgRcvCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: SUBSYSTEM_NAME,
			Name:      NAS_MSG_RCV_COUNTER_NAME,
			Help:      NAS_MSG_RCV_COUNTER_DESC,
		},
		[]string{NAME_LABEL, STATUS_LABEL, CAUSE_LABEL},
	)

	collectors = append(collectors, NasMsgRcvCounter)

	NasMsgSentCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: SUBSYSTEM_NAME,
			Name:      NAS_MSG_SENT_COUNTER_NAME,
			Help:      NAS_MSG_SENT_COUNTER_DESC,
		},
		[]string{NAME_LABEL, STATUS_LABEL, CAUSE_LABEL},
	)

	collectors = append(collectors, NasMsgSentCounter)

	return collectors
}

func removeDigitSuffix(s string) string {
	return suffixRe.ReplaceAllString(s, "")
}

func IncrMetricsRcvNasMsg(msg message.Message, isStatusSuccess *bool, cause *string) {
	if IsNasMetricsEnabled() {
		nasMessageIe := getMessageStrFromGmmMessage(msg)
		metricCause := ""
		if nasMessageIe.cause != nil {
			metricCause = removeDigitSuffix(nasMessageIe.cause.String())
		}
		metricStatus := utils.FailureMetric

		if cause != nil && *cause != "" {
			metricCause = *cause
		}

		if isStatusSuccess != nil && *isStatusSuccess {
			metricStatus = utils.SuccessMetric
		}

		NasMsgRcvCounter.With(prometheus.Labels{
			NAME_LABEL:   nasMessageIe.nasMessageType,
			STATUS_LABEL: metricStatus,
			CAUSE_LABEL:  metricCause,
		}).Inc()
	}
}

func IncrMetricsSentNasMsgs(msgType string, isStatusSuccess *bool, cause5GMM uint8, otherCause *string) {
	if IsNasMetricsEnabled() {
		errCause := ""

		if cause5GMM != 0 {
			gmmCause := nasie.Cause5GMM{Value: cause5GMM}
			errCause = removeDigitSuffix(gmmCause.String())
		} else if otherCause != nil {
			errCause = *otherCause
		}

		metricStatus := utils.FailureMetric

		if isStatusSuccess != nil && *isStatusSuccess {
			metricStatus = utils.SuccessMetric
		}

		NasMsgSentCounter.With(prometheus.Labels{
			NAME_LABEL:   msgType,
			STATUS_LABEL: metricStatus,
			CAUSE_LABEL:  errCause,
		}).Inc()
	}
}

type IeFromGmmMessage struct {
	nasMessageType string
	cause          *nasie.Cause5GMM
}

func getMessageStrFromGmmMessage(msg message.Message) IeFromGmmMessage {
	ie := IeFromGmmMessage{nasMessageType: "Unknown gmm message"}

	if msg == nil {
		return ie
	}

	ie.nasMessageType = msg.MsgType().String()

	switch m := msg.(type) {
	case *message.AuthFailure:
		ie.cause = m.Cause5GMM
	case *message.RegRej:
		ie.cause = m.Cause5GMM
	case *message.DLNASTransport:
		ie.cause = m.Cause5GMM
	case *message.DeregReqUETerm:
		ie.cause = m.Cause5GMM
	case *message.SvcRej:
		ie.cause = m.Cause5GMM
	case *message.SecModeRej:
		ie.cause = m.Cause5GMM
	case *message.Status5GMM:
		ie.cause = m.Cause5GMM
	}
	return ie
}
