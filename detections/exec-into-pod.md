# Detection: exec into a pod

An interactive shell in a running container is one of the loudest signals in the
API audit log. It shows up as an access to the `pods/exec` subresource. This is
the entry the lab produced when running `kubectl exec -n app deploy/web -- id`
against the hardened cluster:

```json
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"509bfc41-feea-40d9-9cc5-8e8d52e1eaa6","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/app/pods/web-7b4b9cc658-584z7/exec?command=id&container=nginx&stderr=true&stdout=true","verb":"get","user":{"username":"system:admin","groups":["system:masters","system:authenticated"]},"sourceIPs":["172.18.0.3"],"userAgent":"kubectl/v1.35.2 (linux/amd64) kubernetes/fdc9d74","objectRef":{"resource":"pods","namespace":"app","name":"web-7b4b9cc658-584z7","apiVersion":"v1","subresource":"exec"},"responseStatus":{"metadata":{},"code":101},"requestReceivedTimestamp":"2026-09-11T20:35:46.992010Z","annotations":{"authorization.k8s.io/decision":"allow"}}
```

## The rule in plain terms

Fire when:

- `objectRef.resource == "pods"` **and** `objectRef.subresource == "exec"`

That is the whole signal. Enrich, don't gate, on the rest:

- `user.username` is the actor. Alert when it is a ServiceAccount
  (`system:serviceaccount:*`) or any identity outside your named break-glass and
  CI accounts. A human on a bastion is expected; a workload SA calling exec is not.
- `objectRef.namespace` / `objectRef.name` tell you what was entered.
- `requestURI` carries the command: `?command=id&container=nginx`. Log it.

### One gotcha worth knowing

Do not key the rule on the verb. On this cluster (k8s 1.31+) `kubectl exec` uses
the websocket transport, so the audit verb is **`get`** and the response code is
`101` (switching protocols). Older SPDY clients show up as verb `create`. If your
rule says `verb == "create"` you will silently miss every modern client. Match the
`exec` subresource and accept either verb.

`pods/attach` and `pods/portforward` are the same class of access and are
captured by the same audit policy. Treat them together.

## False positives and tuning

The real source of noise is engineers debugging in production. Two ways to keep
the signal:

- Allowlist the identities that are supposed to exec: named humans going through
  a break-glass role, and nothing else. Everything not on the list alerts.
- Weight by target. An exec into a batch job or a `kube-system` pod is more
  interesting than an exec into a dev namespace. A `command` of `sh`/`bash`
  (interactive) is more interesting than a scripted one-shot.

The clean fix is to make exec rare on purpose: remove standing exec rights, route
debugging through short-lived break-glass grants, and then every exec that is not
tied to an open break-glass request is worth a page.
