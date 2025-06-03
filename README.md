## Install wazuh simple
---
sudo apt update && sudo apt full-upgrade -y
sudo apt install curl apt-transport-https ca-certificates software-properties-common -y 
curl -s0 https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install -a -i -v
---

- c'est finis

## Agent 

--
sudo apt update && sudo apt full-upgrade -y
sudo apt install curl gnupg
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh-archive-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-agent
sudo nano /var/ossec/etc/ossec.conf #changer IP
sudo systemctl daemon-reexec
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
--

- avant, vérifier version:
- /var/ossec/bin/wazuh-agentd -V


# Enregistrer
- Sur manager
---
/var/ossec/bin/manage_agents
---
- A pour ajouter, puis E pour exporter la clé

- Sur agent 
---
sudo /var/ossec/bin/manage_agents
sudo systemctl restart wazuh-agent
---

- Pour verif:
---
/var/ossec/bin/agent_control -l
---

Maintenant Suricata:

l'installer

Ensuite sur la machine agent :
sudo nano /var/ossec/etc/ossec.conf
ajoute dans <ossec_config> en bas:
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
puis : sudo systemctl restart wazuh-agent

Sur la machine MANAGER
sudo nano /var/ossec/etc/decoders/suricata_decoder.xml
<decoder name="suricata-alert">
  <program_name>suricata</program_name>
  <type>json</type>
</decoder>

ensuite creer une regles:
sudo nano /var/ossec/rules/suricata_rule.xml
contenu :
<group name="surcata,">
  <rule id="100100" level="10">
    <decoded_as>suricata-alert</decoded_as>
    <description>Suricata alert detected</description>
    <group>suricata</group>
  </rule>
</group>

redemarre le manager
sudo systemctl restart wazuh-manager

tester que c bon:
/var/ossec/bin/ossec-logtest
regarde dans :
/var/ossec/logs/alerts/alerts.json


