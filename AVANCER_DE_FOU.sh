#!/bin/bash
set -e

echo "---------------------------------------------------------"
echo "Installation intégrée : Wazuh + Suricata + Logstash"
echo "Basé sur les tutoriels officiels Wazuh/Suricata et l'approche standard."
echo ""
echo "Ce script déploie :"
echo "  1. Wazuh SIEM (Manager, Indexer, Dashboard) via wazuh-docker (v4.11.0)"
echo "  2. Un agent Wazuh (déployé 'comme d'habitude' en conteneur)"
echo "  3. Suricata en IDS, configuré pour capturer sur l'interface wlp3s0"
echo "     et avec HOME_NET défini sur [172.16.84.0/24] (à adapter à votre environnement)"
echo "     Le dossier de règles personnalisées est monté et vous pouvez y ajouter vos règles."
echo "  4. Logstash pour ingérer le fichier /var/log/suricata/eve.json et l'envoyer vers Elasticsearch."
echo ""
echo "Avant de lancer, assurez-vous d'avoir désactivé le offloading sur wlp3s0 :"
echo "  sudo ethtool -K wlp3s0 rx off tx off"
echo "---------------------------------------------------------"
echo "Tapez 1 pour lancer l'installation complète :"
read install_choice
if [ "$install_choice" -ne 1 ]; then
    echo "Installation annulée."
    exit 0
fi

#########################################################################
# PARTIE 1 : Déploiement du SIEM Wazuh (Manager, Indexer, Dashboard)
#########################################################################
BASE_DIR=$(pwd)
echo "[WAZUH] Déploiement du SIEM Wazuh..."
cd "$BASE_DIR"

# Cloner le dépôt wazuh-docker s'il n'existe pas déjà
if [ ! -d "$BASE_DIR/wazuh-docker" ]; then
    echo "[WAZUH] Clonage du dépôt wazuh-docker (branche v4.11.0)..."
    git clone https://github.com/wazuh/wazuh-docker.git -b v4.11.0
else
    echo "[WAZUH] Le dépôt wazuh-docker existe déjà, utilisation de l'existant."
fi

cd "$BASE_DIR/wazuh-docker/single-node/"

echo "[WAZUH] Génération des certificats pour l'indexer..."
docker-compose -f generate-indexer-certs.yml up --build --abort-on-container-exit
docker-compose -f generate-indexer-certs.yml down --remove-orphans

echo "[WAZUH] Démarrage des services (Manager, Indexer, Dashboard)..."
docker-compose -f docker-compose.yml up -d
sleep 5

# Récupérer l'IP du manager (via docker inspect)
MANAGER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' single-node-wazuh.manager-1)
echo "[WAZUH] Manager IP détectée : $MANAGER_IP"
echo "[WAZUH] Dashboard accessible sur https://localhost (Identifiants : admin / SecretPassword)"
cd "$BASE_DIR"

#########################################################################
# PARTIE 1-bis : Déploiement de l'agent Wazuh (comme d'habitude)
#########################################################################
echo "[WAZUH] Déploiement de l'agent Wazuh en conteneur..."
cat > docker-compose.agent.yml <<'EOF'
version: '3'
services:
  wazuh-agent:
    container_name: wazuh-agent
    image: ubuntu:20.04
    hostname: wazuh-agent
    privileged: true
    restart: unless-stopped
    extra_hosts:
      - "wazuh-manager:<MANAGER_IP>"
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    command: >
      bash -c "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl gnupg &&
      curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - &&
      echo 'deb https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list &&
      apt-get update &&
      apt-get install -y wazuh-agent=4.11.0-1 &&
      sed -i 's/MANAGER_IP/<MANAGER_IP>/g' /var/ossec/etc/ossec.conf &&
      /var/ossec/bin/agent-auth -A wazuh-agent -m '<MANAGER_IP>' &&
      /var/ossec/bin/wazuh-control start &&
      tail -f /var/ossec/logs/ossec.log"
EOF
# Remplacer le placeholder avec l'IP réelle du manager
sed -i "s|<MANAGER_IP>|${MANAGER_IP}|g" docker-compose.agent.yml
docker-compose -f docker-compose.agent.yml up -d

#########################################################################
# PARTIE 2 : Déploiement de Suricata (IDS)
#########################################################################
echo "[SURICATA] Déploiement de Suricata..."
NIDS_DIR="$BASE_DIR/nids"
mkdir -p "$NIDS_DIR"
cd "$NIDS_DIR"

# Fichier de configuration de Suricata (configuration minimale)
cat > suricata.yaml <<EOF
---
vars:
  address-groups:
    HOME_NET: "[172.16.84.0/24]"   # Adaptez ce réseau à votre environnement
  EXTERNAL-NET: "!\$HOME_NET"
  SQL-SERVERS: []
  ORACLE-PORTS: []

detect:
  ip-only: no

logging:
  default-log-level: info
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        filename: /var/log/suricata/suricata.log
    - eve:
        enabled: yes
        filetype: regular
        filename: /var/log/suricata/eve.json
        types:
          - alert
          - http
          - dns
          - tls
          - flow

default-rule-path: /var/lib/suricata/rules
rule-files:
  - /etc/suricata/custom_rules/custom.rules
EOF

# Création du répertoire pour les règles personnalisées
mkdir -p custom_rules
# Vous pouvez ajouter ici vos règles ; par défaut, ajout d'une règle de test ICMP
cat > custom_rules/custom.rules <<EOF
alert icmp any any -> any any (msg:"ALERTE TEST ICMP"; sid:1000002; rev:1;)
EOF

# Création du répertoire pour les logs et du fichier de sortie eve.json
mkdir -p suricata-logs
touch suricata-logs/eve.json
chmod 666 suricata-logs/eve.json

# Docker-compose pour Suricata
cat > docker-compose.yml <<EOF
version: '3'
services:
  suricata:
    container_name: suricata
    image: jasonish/suricata:latest
    cap_add:
      - NET_ADMIN
      - NET_RAW
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./suricata.yaml:/etc/suricata/suricata.yaml:ro
      - ./suricata-logs:/var/log/suricata
      - ./custom_rules:/etc/suricata/custom_rules:ro
    command: /usr/bin/suricata -c /etc/suricata/suricata.yaml --pcap=wlp3s0
EOF
docker-compose up -d

#########################################################################
# PARTIE 3 : Déploiement de Logstash
#########################################################################
echo "[LOGSTASH] Déploiement de Logstash..."
LOGSTASH_DIR="$BASE_DIR/logstash"
mkdir -p "$LOGSTASH_DIR"
cd "$LOGSTASH_DIR"

# Configuration Logstash pour lire le fichier eve.json
cat > logstash.conf <<EOF
input {
  file {
    path => "${NIDS_DIR}/suricata-logs/eve.json"
    start_position => "beginning"
    sincedb_path => "/tmp/sincedb_suricata"
    codec => "json"
  }
}

filter {
  # Vous pouvez ajouter ici des filtres (par exemple grok ou mutate)
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "suricata-logs-%{+YYYY.MM.dd}"
  }
  stdout { codec => rubydebug }
}
EOF

cat > docker-compose.logstash.yml <<EOF
version: '3'
services:
  logstash:
    image: docker.elastic.co/logstash/logstash:7.17.0
    container_name: logstash
    network_mode: host
    volumes:
      - ${LOGSTASH_DIR}/logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
      - ${NIDS_DIR}/suricata-logs:/suricata-logs:ro
EOF
docker-compose -f docker-compose.logstash.yml up -d

cd "$BASE_DIR"

#########################################################################
# PARTIE 4 : Instructions pour l'intégration et le test
#########################################################################
echo "---------------------------------------------------------"
echo "Déploiement complet."
echo ""
echo "Votre environnement est désormais déployé :"
echo "  - Le SIEM Wazuh (Manager, Indexer, Dashboard) est accessible sur https://localhost"
echo "    (Identifiants : admin / SecretPassword)"
echo "  - L'agent Wazuh est déployé (vérifiez ses logs via 'docker logs -f wazuh-agent')"
echo "  - Suricata capture le trafic sur l'interface wlp3s0 et écrit les alertes dans /var/log/suricata/eve.json"
echo "  - Logstash lit ce fichier et envoie les évènements vers Elasticsearch (utilisé par Wazuh Indexer)"
echo ""
echo "Pour intégrer les alertes de Suricata dans Wazuh, ajoutez la ligne suivante dans le fichier /var/ossec/etc/ossec.conf"
echo "sur le serveur Wazuh (ou dans la configuration de Filebeat utilisé par Wazuh) :"
echo "  <localfile>"
echo "    <log_format>json</log_format>"
echo "    <location>/var/log/suricata/eve.json</location>"
echo "  </localfile>"
echo ""
echo "Ensuite, pour tester la capture IDS, vous pouvez générer du trafic sur l'interface wlp3s0 (exemple):"
echo "  ping -c 10 172.16.84.39"
echo "  (Assurez-vous que HOME_NET dans suricata.yaml couvre bien cette IP.)"
echo ""
echo "Vous pouvez également consulter directement le fichier eve.json dans le conteneur Suricata :"
echo "    docker exec -it suricata ls -la /var/log/suricata"
echo "    docker exec -it suricata cat /var/log/suricata/eve.json"
echo "---------------------------------------------------------"
