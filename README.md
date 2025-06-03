## Install wazuh simple
---
sudo apt update && sudo apt full-upgrade -y
sudo apt install curl apt-transport-https ca-certificates software-properties-common -y 
curl -s0 https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install -a -i -v
---

- c'est finis

## Agent 

---
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
---

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
