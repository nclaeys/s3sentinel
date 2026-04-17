package s3

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractBucketAndKey(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		host           string
		proxyHost      string
		expectedBucket string
		expectedKey    string
	}{
		// Path-style
		{
			name:           "path-style bucket only",
			url:            "http://s3.example.com/mybucket",
			proxyHost:      "s3.example.com",
			expectedBucket: "mybucket",
			expectedKey:    "",
		},
		{
			name:           "path-style bucket and key",
			url:            "http://s3.example.com/mybucket/mykey",
			proxyHost:      "s3.example.com",
			expectedBucket: "mybucket",
			expectedKey:    "mykey",
		},
		{
			name:           "path-style bucket and nested key",
			url:            "http://s3.example.com/mybucket/prefix/to/mykey",
			proxyHost:      "s3.example.com",
			expectedBucket: "mybucket",
			expectedKey:    "prefix/to/mykey",
		},
		{
			name:           "path-style root (no bucket)",
			url:            "http://s3.example.com/",
			proxyHost:      "s3.example.com",
			expectedBucket: "",
			expectedKey:    "",
		},
		// Virtual-hosted-style
		{
			name:           "virtual-hosted bucket only",
			url:            "http://mybucket.s3.example.com/",
			host:           "mybucket.s3.example.com",
			proxyHost:      "s3.example.com",
			expectedBucket: "mybucket",
			expectedKey:    "",
		},
		{
			name:           "virtual-hosted bucket and key",
			url:            "http://mybucket.s3.example.com/mykey",
			host:           "mybucket.s3.example.com",
			proxyHost:      "s3.example.com",
			expectedBucket: "mybucket",
			expectedKey:    "mykey",
		},
		{
			name:           "virtual-hosted bucket and nested key",
			url:            "http://mybucket.s3.example.com/prefix/to/mykey",
			host:           "mybucket.s3.example.com",
			proxyHost:      "s3.example.com",
			expectedBucket: "mybucket",
			expectedKey:    "prefix/to/mykey",
		},
		// Port stripping
		{
			name:           "path-style with port",
			url:            "http://s3.example.com:9000/mybucket/mykey",
			host:           "s3.example.com:9000",
			proxyHost:      "s3.example.com",
			expectedBucket: "mybucket",
			expectedKey:    "mykey",
		},
		{
			name:           "virtual-hosted with port",
			url:            "http://mybucket.s3.example.com:9000/mykey",
			host:           "mybucket.s3.example.com:9000",
			proxyHost:      "s3.example.com",
			expectedBucket: "mybucket",
			expectedKey:    "mykey",
		},
		// No proxyHost
		{
			name:           "no proxyHost, path-style",
			url:            "http://s3.amazonaws.com/mybucket/mykey",
			proxyHost:      "",
			expectedBucket: "mybucket",
			expectedKey:    "mykey",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, tc.url, nil)
			assert.NoError(t, err)
			if tc.host != "" {
				r.Host = tc.host
			}

			bucket, key := ExtractBucketAndKey(r, tc.proxyHost)
			assert.Equal(t, tc.expectedBucket, bucket)
			assert.Equal(t, tc.expectedKey, key)
		})
	}
}

func TestParse(t *testing.T) {
	const proxyHost = "s3.example.com"

	makeReq := func(method, rawURL string, headers ...string) *http.Request {
		r, err := http.NewRequest(method, rawURL, nil)
		if err != nil {
			panic(err)
		}
		for i := 0; i+1 < len(headers); i += 2 {
			r.Header.Set(headers[i], headers[i+1])
		}
		return r
	}

	tests := []struct {
		name string
		req  *http.Request
		want S3RequestContext
	}{
		{
			name: "ListBuckets",
			req:  makeReq(http.MethodGet, "http://s3.example.com/"),
			want: S3RequestContext{Action: ActionListBuckets},
		},
		{
			name: "unknown method on root",
			req:  makeReq(http.MethodPost, "http://s3.example.com/"),
			want: S3RequestContext{Action: ActionUnknown},
		},

		{
			name: "HeadBucket",
			req:  makeReq(http.MethodHead, "http://s3.example.com/mybucket"),
			want: S3RequestContext{Action: ActionHeadBucket, Bucket: "mybucket"},
		},
		{
			name: "CreateBucket",
			req:  makeReq(http.MethodPut, "http://s3.example.com/mybucket"),
			want: S3RequestContext{Action: ActionCreateBucket, Bucket: "mybucket"},
		},
		{
			name: "DeleteBucket",
			req:  makeReq(http.MethodDelete, "http://s3.example.com/mybucket"),
			want: S3RequestContext{Action: ActionDeleteBucket, Bucket: "mybucket"},
		},
		{
			name: "ListObjects",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket"),
			want: S3RequestContext{Action: ActionListObjects, Bucket: "mybucket"},
		},
		{
			name: "ListObjectsV2",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket?list-type=2"),
			want: S3RequestContext{Action: ActionListObjectsV2, Bucket: "mybucket"},
		},
		{
			name: "GetBucketAcl",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket?acl"),
			want: S3RequestContext{Action: ActionGetBucketAcl, Bucket: "mybucket"},
		},
		{
			name: "PutBucketAcl",
			req:  makeReq(http.MethodPut, "http://s3.example.com/mybucket?acl"),
			want: S3RequestContext{Action: ActionPutBucketAcl, Bucket: "mybucket"},
		},
		{
			name: "GetBucketLocation",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket?location"),
			want: S3RequestContext{Action: ActionGetBucketLocation, Bucket: "mybucket"},
		},
		{
			name: "GetBucketVersioning",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket?versioning"),
			want: S3RequestContext{Action: ActionGetBucketVersioning, Bucket: "mybucket"},
		},
		{
			name: "PutBucketVersioning",
			req:  makeReq(http.MethodPut, "http://s3.example.com/mybucket?versioning"),
			want: S3RequestContext{Action: ActionPutBucketVersioning, Bucket: "mybucket"},
		},
		{
			name: "GetBucketCors",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket?cors"),
			want: S3RequestContext{Action: ActionGetBucketCors, Bucket: "mybucket"},
		},
		{
			name: "PutBucketCors",
			req:  makeReq(http.MethodPut, "http://s3.example.com/mybucket?cors"),
			want: S3RequestContext{Action: ActionPutBucketCors, Bucket: "mybucket"},
		},
		{
			name: "DeleteBucketCors",
			req:  makeReq(http.MethodDelete, "http://s3.example.com/mybucket?cors"),
			want: S3RequestContext{Action: ActionDeleteBucketCors, Bucket: "mybucket"},
		},
		{
			name: "ListMultipartUploads",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket?uploads"),
			want: S3RequestContext{Action: ActionListMultipartUploads, Bucket: "mybucket"},
		},
		{
			name: "DeleteObjects",
			req:  makeReq(http.MethodPost, "http://s3.example.com/mybucket?delete"),
			want: S3RequestContext{Action: ActionDeleteObjects, Bucket: "mybucket"},
		},
		{
			name: "unknown POST on bucket",
			req:  makeReq(http.MethodPost, "http://s3.example.com/mybucket"),
			want: S3RequestContext{Action: ActionUnknown, Bucket: "mybucket"},
		},
		{
			name: "unknown method on bucket",
			req:  makeReq(http.MethodPatch, "http://s3.example.com/mybucket"),
			want: S3RequestContext{Action: ActionUnknown, Bucket: "mybucket"},
		},

		{
			name: "GetObject",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket/mykey"),
			want: S3RequestContext{Action: ActionGetObject, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "HeadObject",
			req:  makeReq(http.MethodHead, "http://s3.example.com/mybucket/mykey"),
			want: S3RequestContext{Action: ActionHeadObject, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "PutObject",
			req:  makeReq(http.MethodPut, "http://s3.example.com/mybucket/mykey"),
			want: S3RequestContext{Action: ActionPutObject, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "DeleteObject",
			req:  makeReq(http.MethodDelete, "http://s3.example.com/mybucket/mykey"),
			want: S3RequestContext{Action: ActionDeleteObject, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "CopyObject",
			req:  makeReq(http.MethodPut, "http://s3.example.com/mybucket/mykey", "X-Amz-Copy-Source", "/srcbucket/srckey"),
			want: S3RequestContext{Action: ActionCopyObject, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "GetObjectAcl",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket/mykey?acl"),
			want: S3RequestContext{Action: ActionGetObjectAcl, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "PutObjectAcl",
			req:  makeReq(http.MethodPut, "http://s3.example.com/mybucket/mykey?acl"),
			want: S3RequestContext{Action: ActionPutObjectAcl, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "GetObjectTagging",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket/mykey?tagging"),
			want: S3RequestContext{Action: ActionGetObjectTagging, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "PutObjectTagging",
			req:  makeReq(http.MethodPut, "http://s3.example.com/mybucket/mykey?tagging"),
			want: S3RequestContext{Action: ActionPutObjectTagging, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "DeleteObjectTagging",
			req:  makeReq(http.MethodDelete, "http://s3.example.com/mybucket/mykey?tagging"),
			want: S3RequestContext{Action: ActionDeleteObjectTagging, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "CreateMultipartUpload",
			req:  makeReq(http.MethodPost, "http://s3.example.com/mybucket/mykey?uploads"),
			want: S3RequestContext{Action: ActionCreateMultipartUpload, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "UploadPart",
			req:  makeReq(http.MethodPut, "http://s3.example.com/mybucket/mykey?partNumber=1&uploadId=abc"),
			want: S3RequestContext{Action: ActionUploadPart, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "CompleteMultipartUpload",
			req:  makeReq(http.MethodPost, "http://s3.example.com/mybucket/mykey?uploadId=abc"),
			want: S3RequestContext{Action: ActionCompleteMultipartUpload, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "AbortMultipartUpload",
			req:  makeReq(http.MethodDelete, "http://s3.example.com/mybucket/mykey?uploadId=abc"),
			want: S3RequestContext{Action: ActionAbortMultipartUpload, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "ListParts",
			req:  makeReq(http.MethodGet, "http://s3.example.com/mybucket/mykey?uploadId=abc"),
			want: S3RequestContext{Action: ActionListParts, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "unknown POST on object",
			req:  makeReq(http.MethodPost, "http://s3.example.com/mybucket/mykey"),
			want: S3RequestContext{Action: ActionUnknown, Bucket: "mybucket", Key: "mykey"},
		},
		{
			name: "unknown method on object",
			req:  makeReq(http.MethodPatch, "http://s3.example.com/mybucket/mykey"),
			want: S3RequestContext{Action: ActionUnknown, Bucket: "mybucket", Key: "mykey"},
		},

		{
			name: "virtual-hosted GetObject",
			req: func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, "http://mybucket.s3.example.com/prefix/mykey", nil)
				r.Host = "mybucket.s3.example.com"
				return r
			}(),
			want: S3RequestContext{Action: ActionGetObject, Bucket: "mybucket", Key: "prefix/mykey"},
		},
		{
			name: "virtual-hosted ListObjects",
			req: func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, "http://mybucket.s3.example.com/", nil)
				r.Host = "mybucket.s3.example.com"
				return r
			}(),
			want: S3RequestContext{Action: ActionListObjects, Bucket: "mybucket"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.req, proxyHost)
			assert.Equal(t, tc.want, got)
		})
	}
}
