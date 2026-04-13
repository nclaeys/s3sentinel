# What each approach actually does

## proxy

The proxy sits permanently in the data path. Every byte of every request and response flows through it. Identity comes from the OIDC JWT the client passes on each call; the proxy validates it, checks   
OPA, re-signs, and forwards.

Client ──[every S3 request]──► Proxy ──► OVH S3           
JWT on every call

## STS endpoint

STS (Security Token Service) is a credential vending machine. The client exchanges a long-lived OIDC token for short-lived fake credentials (AccessKeyID + SecretAccessKey + SessionToken). The SDK then  
handles all subsequent S3 calls using those credentials, handling refresh automatically.

In AWS proper, those temporary credentials carry IAM scoped policies — OVH S3 cannot honour them. So you still need the proxy in the data path to enforce policy. STS changes the authentication story,   
not the enforcement story.

Client ──[exchange JWT for temp creds]──► STS             
Client ──[every S3 request, signed with temp creds]──► Proxy ──► OVH S3

The proxy validates the fake credentials (the SessionToken can be a signed JWT containing principal + groups + expiry — stateless) and continues to check OPA on every request.
                                                                                                                                                                                                            
                                                                                                                                                                                                      
## Pros and cons

### Proxy-only (current)

#### Pros:
 
- single service, simple deployment
- policy enforced on every request in real time — revoking access takes effect immediately
- no state to maintain — no credential store, no TTL tracking
- JWT validation is well-understood; JWKS key rotation is automatic

#### Cons:
- every byte of data flows through the proxy — bandwidth, latency, and scaling cost
- awkward SDK integration — clients must inject the JWT in a custom header on every call, which
- JWT lifetime management falls on the client — short-lived JWTs mean frequent refresh logic the client must implement manually
- the proxy sees all object contents (uploads and downloads) — a concern if the proxy is

The proxy-only approach solves enforcement correctly but has a poor developer experience. Every SDK integration requires custom code.

### STS + Proxy

#### Pros:
- standard SDK integration — AssumeRoleWithWebIdentity is natively supported by every AWS SDK; credential refresh is automatic and transparent to the application
- aws configure, boto3, the AWS CLI, Terraform S3 backends, Spark,
- credential TTL (e.g. 1 hour) bounds how long a stolen credential is valid even without explicit revocation
- clean audit trail at issuance — you know exactly when and to whom credentials were granted

#### Cons:
- two services to deploy, operate, and keep available — STS becomes a dependency of the
- policy changes don't take effect until the current credential expires — a user whose access is revoked can keep using their in-flight credentials until TTL
- the proxy must now validate the fake credentials rather than a standard JWT — either by storing a
- credential revocation before TTL is hard — requires a blocklist, which adds state

The STS + proxy approach gives you full AWS SDK compatibility at the cost of architectural complexity, and introduces a window (the credential TTL) during which revoked access still works.
                                                                                                                                                                                                       
## Chosen solution

As the users will interact directly with the S3 API using various tools (boto3, Spark, DuckDB, AWS CLI), the STS + proxy approach is more user-friendly and will likely drive higher adoption. The real-time revocation of the proxy-only approach is a strong advantage, but the improved developer experience of STS is more important for our use case.
