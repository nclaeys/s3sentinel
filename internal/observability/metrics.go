package observability

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	// RequestsTotal counts every completed request by S3 action and HTTP status.
	RequestsTotal *prometheus.CounterVec

	// RequestDuration records end-to-end latency per S3 action.
	RequestDuration *prometheus.HistogramVec

	// JWTValidationsTotal counts JWT validation outcomes.
	JWTValidationsTotal *prometheus.CounterVec

	// OPAEvaluationsTotal counts OPA policy outcomes.
	OPAEvaluationsTotal *prometheus.CounterVec

	// OPAEvaluationDuration records how long OPA takes to respond.
	OPAEvaluationDuration prometheus.Histogram

	// BackendRequestsTotal counts responses received from the upstream S3 service.
	BackendRequestsTotal *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "s3sentinel_http_requests_total",
			Help: "Total S3 proxy requests, labelled by S3 action and HTTP response status code.",
		}, []string{"action", "status"}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "s3sentinel_http_request_duration_seconds",
			Help:    "End-to-end request latency in seconds, labelled by S3 action.",
			Buckets: prometheus.DefBuckets,
		}, []string{"action"}),

		JWTValidationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "s3sentinel_jwt_validations_total",
			Help: `JWT validation outcomes. "result" is one of: success, error.`,
		}, []string{"result"}),

		OPAEvaluationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "s3sentinel_opa_evaluations_total",
			Help: `OPA policy evaluation outcomes. "result" is one of: allow, deny, error.`,
		}, []string{"result"}),

		OPAEvaluationDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "s3sentinel_opa_evaluation_duration_seconds",
			Help:    "Time spent waiting for an OPA policy decision.",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		}),

		BackendRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "s3sentinel_backend_requests_total",
			Help: "HTTP responses received from the upstream S3 backend, labelled by status code.",
		}, []string{"status"}),
	}

	reg.MustRegister(
		m.RequestsTotal,
		m.RequestDuration,
		m.JWTValidationsTotal,
		m.OPAEvaluationsTotal,
		m.OPAEvaluationDuration,
		m.BackendRequestsTotal,
	)
	return m
}
