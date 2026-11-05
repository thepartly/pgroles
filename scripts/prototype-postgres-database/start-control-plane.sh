#!/usr/bin/env bash
# Minimal control plane for the PostgresDatabase prototype: etcd + kube-apiserver,
# no kubelet. The operator runs on the host against this API server.
set -euo pipefail
D=/opt/k8s/state
mkdir -p $D
cd $D
if [ ! -f sa.key ]; then
  openssl genrsa -out sa.key 2048 2>/dev/null
  openssl rsa -in sa.key -pubout -out sa.pub 2>/dev/null
  # A CA and a separate server certificate: rustls rejects a self-signed
  # certificate used as both.
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.cnf
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 7 -subj "/CN=local-ca" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout apiserver.key -out apiserver.csr -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in apiserver.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out apiserver.crt -days 7 -extfile san.cnf 2>/dev/null
  echo "admin-token,admin,admin,system:masters" > tokens.csv
fi
nohup /opt/k8s/etcd-v3.5.15-linux-amd64/etcd --data-dir $D/etcd \
  --listen-client-urls http://127.0.0.1:2379 --advertise-client-urls http://127.0.0.1:2379 \
  > $D/etcd.log 2>&1 &
sleep 2
nohup /opt/k8s/kube-apiserver --etcd-servers=http://127.0.0.1:2379 \
  --secure-port=6443 --bind-address=127.0.0.1 \
  --tls-cert-file=$D/apiserver.crt --tls-private-key-file=$D/apiserver.key \
  --token-auth-file=$D/tokens.csv --authorization-mode=RBAC \
  --service-account-key-file=$D/sa.pub --service-account-signing-key-file=$D/sa.key \
  --service-account-issuer=https://kubernetes.default.svc \
  --service-cluster-ip-range=10.96.0.0/16 \
  > $D/apiserver.log 2>&1 &
cat > $D/kubeconfig <<KC
apiVersion: v1
kind: Config
clusters:
- cluster: {server: https://127.0.0.1:6443, certificate-authority: $D/ca.crt}
  name: local
users:
- name: admin
  user: {token: admin-token}
contexts:
- context: {cluster: local, user: admin}
  name: local
current-context: local
KC
for i in $(seq 1 60); do
  KUBECONFIG=$D/kubeconfig kubectl get --raw /readyz >/dev/null 2>&1 && { echo ready; exit 0; }
  sleep 1
done
echo "apiserver not ready"; tail -20 $D/apiserver.log; exit 1
