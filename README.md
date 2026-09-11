# Hardening a Kubernetes workload, one attack at a time

This is a local lab. Everything runs in k3d (k3s in Docker), no cloud spend. I
stand up a deliberately vulnerable nginx workload, prove four attack paths against
it with real terminal output, fix each one and re-run the attack, then show how
the same moves look in the API audit log so you can alert on them.

The transcripts are the point. Every block below is copied from the cluster.

## Threat model

One assumption: an attacker gets code execution in a single application container.
Maybe an RCE in the app, maybe a poisoned dependency. The container is not the
prize. The question is what that foothold reaches. On a default setup the answer
is "most of the namespace and the API server," and I want to close that down to
"almost nothing" while the app keeps working.

## The cluster, with audit logging on from the start

Audit logging is the fiddly part on k3s, so wire it in at creation. The policy
keeps volume down: full request/response on `pods/exec` and friends, metadata on
secrets, tokens and RBAC changes, and `None` for everything else.

```bash
k3d cluster create sec-lab \
  --volume "$(pwd)/audit-policy.yaml:/var/lib/rancher/k3s/server/audit-policy.yaml@server:0" \
  --k3s-arg "--kube-apiserver-arg=--audit-policy-file=/var/lib/rancher/k3s/server/audit-policy.yaml@server:0" \
  --k3s-arg "--kube-apiserver-arg=--audit-log-path=/var/log/kubernetes/audit.log@server:0"
```

Read it with `docker exec k3d-sec-lab-server-0 cat /var/log/kubernetes/audit.log | jq`.
If the file never appears, the apiserver rejected a flag, so check
`docker logs k3d-sec-lab-server-0`. k3s ships kube-router, so NetworkPolicy
actually enforces here. Do not pass `--disable-network-policy`.

## Baseline: four attack paths

The baseline (`manifests/00-vulnerable.yaml`) is nginx running as root, on the
default ServiceAccount, with its token mounted, and that default SA bound to the
cluster `edit` role. There is a second workload, `internal-api`, as a lateral
target. Exec in and go to work.

**Root, and a mounted token that can read every secret:**

```
$ id
uid=0(root) gid=0(root) groups=0(root)

$ curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/app/secrets
{ "kind": "SecretList", ... "items": [ { "metadata": { "name": "db-credentials", ...
```

**What that token can do (`kubectl auth can-i --list` from inside the pod):**

```
Resources          Verbs
pods               [create delete deletecollection patch update get list watch]
deployments.apps   [create delete deletecollection patch update get list watch]
secrets            ... (full edit across the namespace)
serviceaccounts/token   [create]
```

**Lateral movement, because a flat pod network has no default deny:**

```
$ wget -qO- http://internal-api.app.svc.cluster.local
internal-api: you reached the lateral-movement target
```

**Arbitrary egress:**

```
$ egress example.com -> reachable
```

The cloud metadata endpoint (`169.254.169.254`) just hangs locally, there is no
metadata service in k3d, so I am not going to fake a result. What matters is that
egress is wide open. On EKS this same open egress is the path to the node IAM
role, which is why IRSA and a metadata-blocking egress rule both matter. I show
the egress block below.

## The fixes

One change per commit. Re-run the matching attack each time.

### 01. Stop mounting the token

`automountServiceAccountToken: false`. The app never calls the API, so it has no
business carrying a credential.

```
$ cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat: .../token: No such file or directory
```

### 02. Pod Security Standards: restricted

Label the namespace `pod-security.kubernetes.io/enforce: restricted`, then try to
schedule the old root pod. Admission rejects it verbatim:

```
Error from server (Forbidden): pods "rooted" is forbidden: violates PodSecurity
"restricted:latest": allowPrivilegeEscalation != false ..., unrestricted
capabilities ..., runAsNonRoot != true ..., seccompProfile ...
```

Add the `securityContext` that satisfies it: `runAsNonRoot`, `runAsUser: 1000`,
`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
`capabilities.drop: ["ALL"]`. A non-root user cannot bind port 80, so this uses
the unprivileged nginx image on 8080, with emptyDir mounts for the paths nginx
writes to. Now it is non-root, the root filesystem is read-only, and it still
serves:

```
$ id
uid=1000 gid=0(root) groups=0(root),1000
$ touch /etc/nginx/x
touch: /etc/nginx/x: Read-only file system
$ wget -qO- http://127.0.0.1:8080
<title>Welcome to nginx!</title>
```

### 03. Default-deny network, then the minimum

A default-deny NetworkPolicy on both directions, then DNS to kube-system and
`web -> internal-api` on its port. Watch it break, then come back scoped:

```
# after default-deny, before allows
$ wget internal-api  -> wget: bad address (blocked)

# after allow-dns + web->internal-api
$ wget internal-api  -> internal-api: you reached the lateral-movement target
$ egress example.com -> BLOCKED (exit 1)
```

The lateral hop the attacker wanted still works because the app needs it, but
egress to the internet is gone. For workloads that genuinely need broad egress,
`03-networkpolicy.yaml` also carries the metadata carve-out: allow `0.0.0.0/0`
`except 169.254.169.254/32`. Be honest about the trade-off, that rule reopens
general egress, so prefer real CIDRs when you can. On EKS the carve-out is what
stops a compromised pod from reaching the node role.

### 04. RBAC down to what the app reads

Delete the `edit` binding, replace it with a Role granting `get`/`list` on the one
ConfigMap the app uses. Re-run `can-i --list` and diff against the baseline:

```
$ kubectl auth can-i --list --as=system:serviceaccount:app:default -n app
Resources    Resource Names   Verbs
configmaps   [app-config]     [get list]

can-i list secrets  -> no
can-i create deploy -> no
```

The wall of `edit` verbs is gone. All that is left is read on a single named
ConfigMap.

## Detection

Fixes fail. You still want to see the attack. Re-running exec against the hardened
cluster lands this in the audit log:

```json
{"verb":"get","objectRef":{"resource":"pods","subresource":"exec","namespace":"app","name":"web-..."},"requestURI":".../exec?command=id&container=nginx","responseStatus":{"code":101}}
```

The rule is `objectRef.resource == "pods"` and `subresource == "exec"`. One gotcha
worth the whole exercise: on k8s 1.31+ exec uses websockets, so the verb is `get`,
not `create`. A rule pinned to `create` misses every modern client. Alert on any
non-CI, non-break-glass identity, and tune out engineers debugging in prod with an
allowlist of break-glass accounts. The token-theft path leaves an equally clean
trace: a `list` on `secrets` by `system:serviceaccount:app:default`, user agent
`curl`, with the granting RoleBinding named right in the audit reason. Full
write-ups in `detections/`.

## What this does not cover

PSS is admission-time only. It checks the spec when the pod is created and then
steps out of the way, so it does nothing about a container that escapes after
start. That is runtime, and it wants a runtime tool (Falco or similar), which this
lab leaves as optional. Also out of scope: supply-chain (a malicious image passes
every control here cleanly), runtime evasion, node and control-plane hardening,
and secrets management beyond "do not hand them to every pod." The four fixes
shrink the blast radius of one compromised container. They do not stop it from
being compromised.
