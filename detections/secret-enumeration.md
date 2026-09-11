# Detection: secret enumeration from a pod ServiceAccount

Token theft looks boring in the audit log: it is just a `list` on `secrets`. What
makes it a finding is *who* is asking. A pod-bound ServiceAccount pulling the
secret list is the exact tail end of the token-theft path from Step 3. This is the
line the baseline attack produced:

```json
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"e48f790a-d3d9-4a97-9e7b-e7e866a86c10","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/app/secrets","verb":"list","user":{"username":"system:serviceaccount:app:default","groups":["system:serviceaccounts","system:serviceaccounts:app","system:authenticated"],"extra":{"authentication.kubernetes.io/pod-name":["web-7fc7749b56-9jtnl"]}},"sourceIPs":["10.42.0.10"],"userAgent":"curl/7.88.1","objectRef":{"resource":"secrets","namespace":"app","apiVersion":"v1"},"responseStatus":{"code":200},"annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by RoleBinding \"too-much/app\" of ClusterRole \"edit\" to ServiceAccount \"default/app\""}}
```

Everything you need is in that one record: the actor
(`system:serviceaccount:app:default`), the exact pod it came from
(`authentication.kubernetes.io/pod-name`), the client (`userAgent: curl/7.88.1`,
which is not a client-go user agent), the pod IP, and even the binding that let it
through (`RoleBinding "too-much" ... ClusterRole "edit"`).

## The rule in plain terms

Fire when, inside a short window (say 60 seconds):

- `objectRef.resource == "secrets"` **and** `verb in ("list", "get", "watch")`
- **and** `user.username` starts with `system:serviceaccount:`
- **and** the count from one SA crosses a small threshold (a burst, e.g. 3+)

A single `get` on a named secret a workload owns is normal. A `list` of all
secrets in a namespace, or a rapid series of `get`s across many names, from a
ServiceAccount is not something a well-behaved app does.

Stronger signals to raise severity on:

- `userAgent` is `curl`, `python-requests`, `Go-http-client`, or empty, rather
  than a real `kubectl`/client-go agent. Apps that legitimately read a secret use
  the SDK, not curl.
- The SA is `default`. A workload should never run as the namespace default SA.

## False positives and tuning

Controllers and operators list secrets constantly and legitimately
(cert-manager, ingress controllers, the kubelet). Tune by:

- Allowlisting known infra ServiceAccounts (`kube-system:*`, your operators) and
  scoping the rule to application namespaces.
- Alerting on `list`/`watch` over all secrets separately from `get` on a single
  named secret. The first is enumeration; the second is usually normal use.

The audit reason field closes the loop: it names the RoleBinding that granted
access, so a hit tells you both that enumeration happened and which over-broad
grant to go delete.
