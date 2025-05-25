#!/bin/bash
set -e

NETWORK_NAME="mon_reseau"
SUBNET="172.23.0.0/16"      # Subnet peu probable d'être déjà utilisé, modifiable si besoin
APACHE_IP="172.23.0.10"
BIND_IP="172.23.0.3"
ZONE_NAME="brrbrrpatapim.apagnan"

# 1. Suppression réseau si existe
if docker network inspect $NETWORK_NAME >/dev/null 2>&1; then
  echo "Suppression réseau Docker $NETWORK_NAME..."
  docker network rm $NETWORK_NAME
fi

echo "Création réseau Docker $NETWORK_NAME avec subnet $SUBNET..."
docker network create --subnet=$SUBNET $NETWORK_NAME

# 2. Création fichiers config BIND
mkdir -p bind/zones

cat > bind/named.conf <<EOF
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
    forwarders { 8.8.8.8; 8.8.4.4; };
    dnssec-validation no;
    listen-on { any; };
};

zone "$ZONE_NAME" {
    type master;
    file "/etc/bind/zones/db.$ZONE_NAME";
};
EOF

cat > bind/zones/db.$ZONE_NAME <<EOF
\$TTL 604800
@   IN  SOA ns.$ZONE_NAME. root.$ZONE_NAME. (
        2       ; Serial
        604800  ; Refresh
        86400   ; Retry
        2419200 ; Expire
        604800  ; Negative Cache TTL
)
@   IN  NS  ns.$ZONE_NAME.
ns  IN  A   127.0.0.1
@   IN  A   $APACHE_IP
EOF

# 3. Vérification syntaxe zone DNS
echo "Vérification syntaxe zone DNS..."
docker run --rm -v $(pwd)/bind/zones:/etc/bind/zones:ro --entrypoint named-checkzone internetsystemsconsortium/bind9:9.18 $ZONE_NAME /etc/bind/zones/db.$ZONE_NAME

# 4. Lancement conteneur Apache avec IP fixe
docker rm -f apache 2>/dev/null || true
echo "Lancement conteneur Apache..."
docker run -d --name apache --net $NETWORK_NAME --ip $APACHE_IP httpd:2.4

# 5. Création Dockerfile BIND personnalisé
cat > bind/Dockerfile <<EOF
FROM internetsystemsconsortium/bind9:9.18
COPY named.conf /etc/bind/named.conf
COPY zones /etc/bind/zones
EOF

# 6. Construction image BIND
docker build -t mybind bind

# 7. Lancement conteneur BIND avec IP fixe, ports DNS exposés **sur localhost uniquement**
docker rm -f bind 2>/dev/null || true
echo "Lancement conteneur BIND..."
docker run -d --name bind --net $NETWORK_NAME --ip $BIND_IP \
  -p 127.0.0.1:53:53/udp -p 127.0.0.1:53:53/tcp mybind

sleep 3

# 8. Configuration DNS machine hôte (résolv.conf via systemd-resolved ou modification temporaire)

# Détection systemd-resolved
if systemctl is-active --quiet systemd-resolved; then
  echo "Configuration systemd-resolved pour utiliser DNS localhost..."
  sudo resolvectl dns lo 127.0.0.1
  sudo resolvectl domain lo "~."
else
  echo "Modification temporaire de /etc/resolv.conf pour utiliser DNS localhost..."
  sudo cp /etc/resolv.conf /etc/resolv.conf.backup
  echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf >/dev/null
fi

# 9. Test DNS depuis machine hôte
echo "Test de résolution DNS depuis machine hôte..."
nslookup $ZONE_NAME 127.0.0.1

echo -e "\nScript terminé.\n"
echo " - Le DNS BIND est accessible sur localhost:53."
echo " - Apache est accessible sur $APACHE_IP."
echo " - Tu peux tester la résolution DNS : nslookup $ZONE_NAME 127.0.0.1"
echo " - Vérifie ton /etc/resolv.conf ou systemd-resolved selon ta config."
