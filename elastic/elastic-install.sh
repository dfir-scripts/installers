#!/usr/bin/env bash
# ==============================================================================
# TLN-ELK Native Ubuntu 24.04 Installer
# Installs Elasticsearch 8.17, Logstash 8.17, and Kibana 8.17 via official APT
# repos, then configures the TLN forensic timeline ingestion pipeline and
# Kibana dashboard.
#
# Usage:  sudo bash elastic-install.sh
# ==============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Must be run as root
# ---------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run as root:  sudo bash elastic-install.sh"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "====================================================================="
echo " TLN-ELK Native Ubuntu Installer (Elastic 8.17)"
echo "====================================================================="
echo ""

# ---------------------------------------------------------------------------
# [1/9] Prerequisites
# ---------------------------------------------------------------------------
echo "[1/9] Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq \
  apt-transport-https uuid-runtime gnupg curl wget \
  python3 python3-requests jq

# ---------------------------------------------------------------------------
# [2/9] Elastic APT repository
# ---------------------------------------------------------------------------
echo "[2/9] Adding Elastic APT repository..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
  | tee /etc/apt/sources.list.d/elastic-8.x.list > /dev/null
apt-get update -qq

# ---------------------------------------------------------------------------
# [3/9] Install ELK — MASK services first to prevent auto-start
#
# The Elastic APT post-install hook on Ubuntu 24.04 calls:
#   systemctl start elasticsearch
# This happens BEFORE we can clean the keystore, causing an immediate
# startup failure because the auto-generated SSL keystore entries conflict
# with our security-disabled config.
#
# Masking the units prevents any start attempt during installation.
# We unmask them after the config and keystore are fully prepared.
# ---------------------------------------------------------------------------
echo "[3/9] Installing Elasticsearch, Kibana, and Logstash 8.17..."
echo "    (Masking services to prevent premature auto-start...)"

# Pre-create systemd override dirs so mask works even before packages exist
mkdir -p /etc/systemd/system/elasticsearch.service.d
mkdir -p /etc/systemd/system/kibana.service.d
mkdir -p /etc/systemd/system/logstash.service.d
systemctl mask elasticsearch kibana logstash 2>/dev/null || true

# ES_SKIP_SET_KERNEL_PARAMETERS: prevent the APT hook from modifying sysctl
ES_SKIP_SET_KERNEL_PARAMETERS=true \
  DEBIAN_FRONTEND=noninteractive \
  apt-get install -y elasticsearch=8.17.* kibana=8.17.* logstash=1:8.17.*

# ---------------------------------------------------------------------------
# [4/9] vm.max_map_count (required by Elasticsearch)
# ---------------------------------------------------------------------------
echo "[4/9] Setting vm.max_map_count=262144..."
sysctl -w vm.max_map_count=262144 > /dev/null
if ! grep -q 'vm.max_map_count' /etc/sysctl.conf; then
  echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
fi

# ---------------------------------------------------------------------------
# [5/9] Configure Elasticsearch
# ---------------------------------------------------------------------------
echo "[5/9] Configuring Elasticsearch..."

# Write the full config — all three xpack.security lines are required:
#   xpack.security.enabled: false              — disables auth
#   xpack.security.http.ssl.enabled: false     — disables HTTPS
#   xpack.security.transport.ssl.enabled: false — disables transport SSL
# Without the transport line, ES refuses to start if keystore has SSL entries.
cat > /etc/elasticsearch/elasticsearch.yml << 'ESEOF'
cluster.name: tln-forensics
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
ESEOF

# JVM heap — 1 GB is fine for forensic analysis; increase if you have more RAM
cat > /etc/elasticsearch/jvm.options.d/tln-heap.options << 'JVMEOF'
-Xms1g
-Xmx1g
JVMEOF

# ---------------------------------------------------------------------------
# KEY FIX: Remove auto-generated SSL keystore entries
#
# The Elastic APT post-install script runs elasticsearch-setup-passwords and
# elasticsearch-certutil, which populate the keystore with SSL certificate
# passwords. These entries cause a fatal conflict when security is disabled
# because ES sees the passwords but finds ssl.enabled=false.
#
# We remove them now (while the service is still masked) so the first start
# is clean.
# ---------------------------------------------------------------------------
echo "    Clearing auto-generated SSL keystore entries..."
ES_KEYSTORE=/usr/share/elasticsearch/bin/elasticsearch-keystore

for KEY in \
  xpack.security.transport.ssl.keystore.secure_password \
  xpack.security.transport.ssl.truststore.secure_password \
  xpack.security.http.ssl.keystore.secure_password \
  xpack.security.http.ssl.truststore.secure_password; do
  if $ES_KEYSTORE list 2>/dev/null | grep -q "^${KEY}$"; then
    $ES_KEYSTORE remove "$KEY" 2>/dev/null && echo "    Removed keystore entry: $KEY"
  fi
done

echo "    Keystore entries remaining:"
$ES_KEYSTORE list 2>/dev/null | sed 's/^/      /'

# ---------------------------------------------------------------------------
# Unmask and start Elasticsearch
# ---------------------------------------------------------------------------
systemctl unmask elasticsearch
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

echo "    Waiting for Elasticsearch to start..."
ELAPSED=0
until curl -sf http://localhost:9200/ > /dev/null 2>&1; do
  sleep 5
  ELAPSED=$((ELAPSED + 5))
  if [ $ELAPSED -ge 120 ]; then
    echo ""
    echo "ERROR: Elasticsearch did not start within 120 seconds."
    echo ""
    echo "Diagnostics:"
    echo "  sudo journalctl -u elasticsearch -n 50 --no-pager"
    echo "  sudo cat /var/log/elasticsearch/tln-forensics.log | tail -30"
    echo "  sudo /usr/share/elasticsearch/bin/elasticsearch-keystore list"
    exit 1
  fi
  echo -n "."
done
echo " Elasticsearch is up!"

# ---------------------------------------------------------------------------
# [6/9] Configure Kibana
# ---------------------------------------------------------------------------
echo "[6/9] Configuring Kibana..."
cat > /etc/kibana/kibana.yml << 'KBEOF'
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
KBEOF

systemctl unmask kibana
systemctl enable kibana
systemctl start kibana

echo "    Waiting for Kibana to start (this takes ~60-90 seconds)..."
ELAPSED=0
until curl -sf http://localhost:5601/api/status 2>/dev/null \
  | python3 -c "
import sys, json
try:
    s = json.load(sys.stdin)
    level = s.get('status', {}).get('overall', {}).get('level', '')
    sys.exit(0 if level == 'available' else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
  sleep 5
  ELAPSED=$((ELAPSED + 5))
  if [ $ELAPSED -ge 240 ]; then
    echo ""
    echo "ERROR: Kibana did not start within 240 seconds."
    echo "  sudo journalctl -u kibana -n 50 --no-pager"
    exit 1
  fi
  echo -n "."
done
echo " Kibana is up!"

# ---------------------------------------------------------------------------
# [7/9] TLN ingestion directory
# ---------------------------------------------------------------------------
echo "[7/9] Setting up TLN ingestion directory..."
mkdir -p /opt/tln-data
chmod 777 /opt/tln-data
echo "    Drop .tln and .csv files into: /opt/tln-data/"

# ---------------------------------------------------------------------------
# [8/9] Configure Logstash pipeline
# ---------------------------------------------------------------------------
echo "[8/9] Configuring Logstash pipeline..."

cat > /etc/logstash/conf.d/tln.conf << 'LSEOF'
input {
  file {
    path            => "/opt/tln-data/*.tln"
    start_position  => "beginning"
    sincedb_path    => "/var/lib/logstash/tln_sincedb"
    mode            => "read"
    file_completed_action   => "log"
    file_completed_log_path => "/var/log/logstash/tln-completed.log"
    discover_interval => 5
    stat_interval     => 2
    codec => plain { charset => "UTF-8" }
    tags => ["tln"]
  }
  file {
    path            => "/opt/tln-data/*.csv"
    start_position  => "beginning"
    sincedb_path    => "/var/lib/logstash/tln_sincedb"
    mode            => "read"
    file_completed_action   => "log"
    file_completed_log_path => "/var/log/logstash/tln-completed.log"
    discover_interval => 5
    stat_interval     => 2
    codec => plain { charset => "UTF-8" }
    tags => ["tln"]
  }
}

filter {
  # Drop blank lines and comment lines
  if [message] =~ /^\s*$/ or [message] =~ /^#/ { drop {} }

  # Format 1: pipe-delimited epoch  (epoch|source|host|user|description)
  if [message] =~ /^\d+\|/ {
    grok {
      match => { "message" => "^%{NUMBER:tln_epoch}\|%{DATA:tln_source}\|%{DATA:hostname}\|%{DATA:username}\|%{GREEDYDATA:description}$" }
      tag_on_failure => ["_tln_parse_failure"]
    }
    if "_tln_parse_failure" not in [tags] {
      date {
        match        => ["tln_epoch", "UNIX"]
        target       => "@timestamp"
        remove_field => ["tln_epoch"]
      }
    }
  }
  # Format 2: comma-delimited datetime  (YYYY-MM-DD HH:MM:SS,source,host,user,description)
  else if [message] =~ /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},/ {
    grok {
      match => { "message" => "^%{TIMESTAMP_ISO8601:tln_timestamp},%{DATA:tln_source},%{DATA:hostname},%{DATA:username},%{GREEDYDATA:description}$" }
      tag_on_failure => ["_tln_parse_failure"]
    }
    if "_tln_parse_failure" not in [tags] {
      date {
        match        => ["tln_timestamp", "yyyy-MM-dd HH:mm:ss", "ISO8601"]
        target       => "@timestamp"
        remove_field => ["tln_timestamp"]
      }
    }
  }

  # Drop anything that failed to parse
  if "_tln_parse_failure" in [tags] { drop {} }

  # Clean up whitespace
  mutate { strip => ["tln_source", "hostname", "username", "description"] }

  # Normalise empty fields
  if [hostname]   == "" or ![hostname]   { mutate { replace => { "hostname"   => "-" } } }
  if [username]   == "" or ![username]   { mutate { replace => { "username"   => "-" } } }
  if [tln_source] == "" or ![tln_source] { mutate { replace => { "tln_source" => "UNKNOWN" } } }

  # Remove Logstash metadata fields we don't need
  mutate { remove_field => ["host", "log", "event", "@version"] }
}

output {
  elasticsearch {
    hosts  => ["http://localhost:9200"]
    index  => "tln-%{+YYYY.MM.dd}"
    action => "index"
  }
}
LSEOF

systemctl unmask logstash
systemctl enable logstash
systemctl start logstash

# ---------------------------------------------------------------------------
# [9/9] Load ES index template and Kibana dashboard
# ---------------------------------------------------------------------------
echo "[9/9] Loading ES index template and Kibana dashboard..."

curl -s -X PUT "http://localhost:9200/_index_template/tln" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["tln-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s"
      },
      "mappings": {
        "properties": {
          "@timestamp":  { "type": "date" },
          "tln_source":  { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } } },
          "hostname":    { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } } },
          "username":    { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } } },
          "description": { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 } } },
          "tags":        { "type": "keyword" }
        }
      }
    }
  }' > /dev/null && echo "    ES index template loaded."

# Run the Python dashboard creation script
if [ -f "${SCRIPT_DIR}/create_kibana_dashboard.py" ]; then
  python3 "${SCRIPT_DIR}/create_kibana_dashboard.py"
else
  echo "    Warning: create_kibana_dashboard.py not found next to elastic-install.sh."
  echo "    Run manually after install:  python3 create_kibana_dashboard.py"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "====================================================================="
echo " INSTALLATION COMPLETE"
echo "====================================================================="
echo ""
echo " Services (auto-start on reboot via systemd):"
echo "   sudo systemctl status elasticsearch"
echo "   sudo systemctl status kibana"
echo "   sudo systemctl status logstash"
echo ""
echo " Drop TLN files here to ingest:"
echo "   /opt/tln-data/   (supports .tln and .csv)"
echo ""
echo " Kibana:"
echo "   http://$(hostname -I | awk '{print $1}'):5601"
echo "   Dashboard: TLN Timeline Analysis"
echo "   Set the time range to cover your data's dates"
echo ""
echo " Verify ingestion:"
echo "   curl -s 'http://localhost:9200/tln-*/_count?pretty'"
echo "====================================================================="
