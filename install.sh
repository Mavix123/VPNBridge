#!/bin/bash

# VPN Bridge Manager - Complete Installation Script
# Run as root: sudo bash install-vpn-bridge.sh

set -e

echo "VPN Bridge Manager - Complete Installation Script"
echo "===================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   echo "Usage: sudo bash install-vpn-bridge.sh"
   exit 1
fi

echo -e "${BLUE}Starting VPN Bridge installation...${NC}\n"

# Function to generate random password
generate_shared_secret() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Function to read password securely
read_password() {
    local prompt="$1"
    local password=""
    local char=""
    
    echo -n "$prompt"
    while IFS= read -r -s -n1 char; do
        if [[ $char == $'\0' ]]; then
            break
        elif [[ $char == $'\177' ]]; then  # Backspace
            if [[ ${#password} -gt 0 ]]; then
                password="${password%?}"
                echo -ne '\b \b'
            fi
        else
            password+="$char"
            echo -n '*'
        fi
    done
    echo
    echo "$password"
}

# Collect user credentials
echo -e "${YELLOW}📝 L2TP User Configuration${NC}"
echo "Please provide the L2TP user credentials:"
echo ""

# Get username
while true; do
    echo -n "Enter L2TP username: "
    read L2TP_USERNAME
    if [[ -n "$L2TP_USERNAME" && "$L2TP_USERNAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        break
    else
        echo -e "${RED}Invalid username. Use only letters, numbers, underscore and dash.${NC}"
    fi
done

# Get password
while true; do
    L2TP_PASSWORD=$(read_password "Enter L2TP password: ")
    if [[ ${#L2TP_PASSWORD} -ge 6 ]]; then
        echo ""
        CONFIRM_PASSWORD=$(read_password "Confirm L2TP password: ")
        echo ""
        if [[ "$L2TP_PASSWORD" == "$CONFIRM_PASSWORD" ]]; then
            break
        else
            echo -e "${RED}Passwords don't match. Please try again.${NC}"
        fi
    else
        echo -e "${RED}Password must be at least 6 characters long.${NC}"
    fi
done

# Generate shared secret
SHARED_SECRET=$(generate_shared_secret)

echo ""
echo -e "${GREEN}✓ L2TP Configuration:${NC}"
echo "  Username: $L2TP_USERNAME"
echo "  Password: $(echo "$L2TP_PASSWORD" | sed 's/./*/g')"
echo "  Shared Secret: $SHARED_SECRET"
echo ""

# Confirm configuration
echo -n "Continue with this configuration? (y/N): "
read -r CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

echo ""

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || ip route get 8.8.8.8 | awk '{print $7; exit}' 2>/dev/null || echo "YOUR_SERVER_IP")

# Update system
echo -e "${YELLOW}📦 Updating system packages...${NC}"
apt update

# Install required packages (with error handling for dpkg issues)
echo -e "${YELLOW}📦 Installing required packages...${NC}"

# Try to fix any dpkg issues first
dpkg --configure -a 2>/dev/null || true
apt --fix-broken install -y 2>/dev/null || true

# Install packages one by one to avoid dependency issues
PACKAGES=(
    "apache2"
    "php"
    "php-json"
    "php-curl"
    "pptp-linux"
    "strongswan"
    "xl2tpd"
    "iptables-persistent"
    "net-tools"
    "curl"
    "wget"
    "nano"
    "openssl"
)

for package in "${PACKAGES[@]}"; do
    echo -e "${BLUE}Installing $package...${NC}"
    apt install -y "$package" || {
        echo -e "${YELLOW}Warning: Failed to install $package, continuing...${NC}"
    }
done

# Enable IP forwarding
echo -e "${YELLOW}🌐 Enabling IP forwarding...${NC}"
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Create VPN Bridge directories
echo -e "${YELLOW}📁 Creating directories...${NC}"
mkdir -p /etc/vpn-bridge
mkdir -p /var/www/html/vpn-bridge
mkdir -p /var/log/vpn-bridge

# Set permissions
chmod 755 /etc/vpn-bridge
chmod 755 /var/www/html/vpn-bridge
chmod 755 /var/log/vpn-bridge

# Create initial VPN database
echo -e "${YELLOW}🗄️ Creating initial database...${NC}"
cat > /etc/vpn-bridge/vpn_list.json << 'EOF'
[]
EOF
chmod 600 /etc/vpn-bridge/vpn_list.json

# Configure StrongSwan
echo -e "${YELLOW}🔐 Configuring StrongSwan IPSec...${NC}"

# Create strongswan config
cat > /etc/ipsec.conf << 'EOF'
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@server
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity

conn L2TP-PSK
    authby=secret
    pfs=no
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=%defaultroute
    leftid=$SERVER_IP
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    forceencaps=yes
EOF

# Create IPSec secrets with generated shared secret
cat > /etc/ipsec.secrets << EOF
: PSK "$SHARED_SECRET"
EOF

# Configure xl2tpd
echo -e "${YELLOW}🔗 Configuring xl2tpd L2TP...${NC}"

cat > /etc/xl2tpd/xl2tpd.conf << 'EOF'
[global]
port = 1701

[lns default]
ip range = 10.0.20.10-10.0.20.50
local ip = 10.0.20.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# Create PPP options for xl2tpd
cat > /etc/ppp/options.xl2tpd << 'EOF'
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
noauth
idle 1800
mtu 1410
mru 1410
debug
EOF

# Create CHAP secrets with provided credentials
cat > /etc/ppp/chap-secrets << EOF
# L2TP Users
$L2TP_USERNAME l2tpd $L2TP_PASSWORD *
EOF

# Configure firewall
echo -e "${YELLOW}🔥 Configuring firewall...${NC}"

# IPtables rules for VPN
cat > /etc/iptables/rules.v4 << EOF
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# Basic rules
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# SSH
-A INPUT -p tcp --dport 22 -j ACCEPT

# HTTP/HTTPS for web interface
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# IPSec/L2TP
-A INPUT -p udp --dport 500 -j ACCEPT
-A INPUT -p udp --dport 4500 -j ACCEPT
-A INPUT -p udp --dport 1701 -j ACCEPT
-A INPUT -p esp -j ACCEPT

# L2TP forwarding
-A FORWARD -i ppp+ -j ACCEPT
-A FORWARD -o ppp+ -j ACCEPT

# Drop everything else
-A INPUT -j DROP

COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

# Masquerade for L2TP clients
-A POSTROUTING -s 10.0.20.0/24 -o eth0 -j MASQUERADE

COMMIT
EOF

# Enable and start services
echo -e "${YELLOW}🚀 Starting services...${NC}"

systemctl enable strongswan-starter
systemctl enable xl2tpd
systemctl enable apache2

systemctl restart strongswan-starter
systemctl restart xl2tpd
systemctl restart apache2

# Apply firewall rules
iptables-restore < /etc/iptables/rules.v4

# Create credentials file for reference
echo -e "${YELLOW}💾 Saving credentials...${NC}"
cat > /etc/vpn-bridge/credentials.txt << EOF
# VPN Bridge Manager - L2TP Credentials
# Generated on: $(date)

L2TP_USERNAME=$L2TP_USERNAME
L2TP_PASSWORD=$L2TP_PASSWORD
SHARED_SECRET=$SHARED_SECRET
SERVER_IP=$SERVER_IP

# Connection details for clients:
# Server: $SERVER_IP
# Username: $L2TP_USERNAME
# Password: $L2TP_PASSWORD
# Shared Secret: $SHARED_SECRET
EOF

chmod 600 /etc/vpn-bridge/credentials.txt

# Install PHP API
echo -e "${YELLOW}⚙️ Installing PHP API...${NC}"
cat > /var/www/html/vpn-bridge/api.php << 'PHPEOF'
<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

define('VPN_CONFIG_DIR', '/etc/vpn-bridge');
define('PPP_PEERS_DIR', '/etc/ppp/peers');
define('LOG_FILE', '/var/log/vpn-bridge/bridge.log');
define('ACTIVE_VPN_FILE', VPN_CONFIG_DIR . '/active_vpn.txt');

foreach ([VPN_CONFIG_DIR, dirname(LOG_FILE)] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

class VPNBridge {

    private function log($message, $level = 'INFO') {
        $timestamp = date('Y-m-d H:i:s');
        $logEntry = "[$timestamp] [$level] $message\n";

        if (is_writable(dirname(LOG_FILE)) || is_writable(LOG_FILE)) {
            file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
        } else {
            error_log("VPN-Bridge [$level] $message");
        }
    }

    private function executeCommand($command) {
        $this->log("Executing: $command");
        $output = [];
        $returnCode = 0;

        $sudoCommands = ['iptables', 'ip', 'pon', 'poff', 'ifconfig', 'ps', 'systemctl'];
        $needsSudo = false;

        foreach ($sudoCommands as $sudoCmd) {
            if (strpos($command, $sudoCmd) !== false) {
                $needsSudo = true;
                break;
            }
        }

        if ($needsSudo && strpos($command, 'sudo') !== 0) {
            $command = 'sudo ' . $command;
        }

        exec($command . ' 2>&1', $output, $returnCode);

        $result = [
            'success' => $returnCode === 0,
            'output' => implode("\n", $output),
            'return_code' => $returnCode
        ];

        $this->log("Command result: " . ($result['success'] ? 'SUCCESS' : 'FAILED') . " - " . $result['output']);
        return $result;
    }

    private function detectL2tpNetwork() {
        if (file_exists('/etc/xl2tpd/xl2tpd.conf')) {
            $config = file_get_contents('/etc/xl2tpd/xl2tpd.conf');

            if (preg_match('/ip range\s*=\s*([0-9.]+)-([0-9.]+)/', $config, $matches)) {
                $startIp = $matches[1];
                if (preg_match('/local ip\s*=\s*([0-9.]+)/', $config, $localMatches)) {
                    $localIp = $localMatches[1];
                    $networkParts = explode('.', $localIp);
                    $networkParts[3] = '0';
                    $network = implode('.', $networkParts) . '/24';
                    $this->log("Detected L2TP network from config: $network");
                    return ['network' => $network, 'interface' => 'ppp0'];
                }
            }
        }

        $result = $this->executeCommand("ip addr show ppp0 2>/dev/null");
        if ($result['success'] && strpos($result['output'], 'inet ') !== false) {
            if (preg_match('/inet (\d+\.\d+\.\d+\.\d+)/', $result['output'], $matches)) {
                $ip = $matches[1];
                $networkParts = explode('.', $ip);
                $networkParts[3] = '0';
                $network = implode('.', $networkParts) . '/24';
                $this->log("Detected L2TP network from interface: $network");
                return ['network' => $network, 'interface' => 'ppp0'];
            }
        }

        $this->log("Could not detect L2TP network, using default 10.0.20.0/24");
        return ['network' => '10.0.20.0/24', 'interface' => 'ppp0'];
    }

    private function getPptpGateway() {
        $ifconfig = $this->executeCommand("ifconfig ppp1 2>/dev/null");
        if ($ifconfig['success']) {
            // Sprawdź oba formaty: P-t-P: i destination
            if (preg_match('/P-t-P:(\d+\.\d+\.\d+\.\d+)/', $ifconfig['output'], $matches)) {
                $gateway = $matches[1];
                $this->log("Detected PPTP gateway (P-t-P format): $gateway");
                return $gateway;
            } elseif (preg_match('/destination (\d+\.\d+\.\d+\.\d+)/', $ifconfig['output'], $matches)) {
                $gateway = $matches[1];
                $this->log("Detected PPTP gateway (destination format): $gateway");
                return $gateway;
            }
        }

        $this->log("Could not detect PPTP gateway from ifconfig, trying ip route", 'ERROR');

        // Fallback - sprawdź przez ip route
        $route = $this->executeCommand("ip route show dev ppp1 2>/dev/null");
        if ($route['success']) {
            if (preg_match('/(\d+\.\d+\.\d+\.\d+) dev ppp1/', $route['output'], $matches)) {
                $gateway = $matches[1];
                $this->log("Detected PPTP gateway from route: $gateway");
                return $gateway;
            }
        }

        $this->log("Could not detect PPTP gateway - all methods failed", 'ERROR');
        return null;
    }

    private function getRemoteNetworks() {
        $networks = [];

        $ifconfig = $this->executeCommand("ifconfig ppp1 2>/dev/null");
        if ($ifconfig['success']) {
            if (preg_match('/P-t-P:(\d+\.\d+\.\d+\.\d+)/', $ifconfig['output'], $matches)) {
                $remoteIp = $matches[1];
                $networks[] = $remoteIp . '/32';
                $this->log("Found PPTP remote gateway: $remoteIp");

                $routes = $this->executeCommand("ip route show dev ppp1 2>/dev/null");
                if ($routes['success']) {
                    $lines = explode("\n", $routes['output']);
                    foreach ($lines as $line) {
                        if (preg_match('/^(\d+\.\d+\.\d+\.\d+\/\d+)/', trim($line), $matches)) {
                            if ($matches[1] !== '0.0.0.0/0') {
                                $networks[] = $matches[1];
                            }
                        }
                    }
                }
            }
        }

        $this->log("Detected remote networks: " . implode(', ', $networks));
        return $networks;
    }

    public function getVpnList() {
        $vpns = [];
        $configFile = VPN_CONFIG_DIR . '/vpn_list.json';

        if (file_exists($configFile) && is_readable($configFile)) {
            $content = file_get_contents($configFile);
            $vpns = json_decode($content, true) ?: [];
        }

        $activeVpn = $this->getActiveVpn();
        foreach ($vpns as &$vpn) {
            $vpn['is_active'] = ($activeVpn === $vpn['id']);
            $vpn['status'] = $this->getVpnStatus($vpn['id']);
        }

        return $vpns;
    }

    public function addVpn($data) {
        $required = ['name', 'server', 'username', 'password'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new Exception("Missing required field: $field");
            }
        }

        $vpnId = strtolower(preg_replace('/[^a-zA-Z0-9]/', '_', $data['name']));

        $vpn = [
            'id' => $vpnId,
            'name' => $data['name'],
            'server' => $data['server'],
            'username' => $data['username'],
            'password' => $data['password'],
            'description' => $data['description'] ?? '',
            'created_at' => date('Y-m-d H:i:s'),
            'last_connected' => null
        ];

        $this->createPptpConfig($vpn);
        $this->saveVpn($vpn);
        $this->log("Added VPN: {$vpn['name']} (ID: {$vpn['id']})");

        return ['success' => true, 'vpn_id' => $vpnId];
    }

    public function updateVpn($vpnId, $data) {
        $vpns = $this->getVpnList();
        $vpn = null;

        foreach ($vpns as $v) {
            if ($v['id'] === $vpnId) {
                $vpn = $v;
                break;
            }
        }

        if (!$vpn) {
            throw new Exception("VPN not found: $vpnId");
        }

        foreach ($data as $key => $value) {
            if ($key !== 'id' && isset($vpn[$key])) {
                $vpn[$key] = $value;
            }
        }

        $this->createPptpConfig($vpn);
        $this->saveVpn($vpn);
        $this->log("Updated VPN: {$vpn['name']}");

        return ['success' => true];
    }

    public function deleteVpn($vpnId) {
        $activeVpn = $this->getActiveVpn();
        if ($activeVpn === $vpnId) {
            $this->disconnectVpn();
        }

        $peerFile = PPP_PEERS_DIR . "/$vpnId";
        if (file_exists($peerFile)) {
            unlink($peerFile);
        }

        $vpns = $this->getVpnList();
        $vpns = array_filter($vpns, function($vpn) use ($vpnId) {
            return $vpn['id'] !== $vpnId;
        });

        $this->saveVpnList(array_values($vpns));
        $this->log("Deleted VPN: $vpnId");

        return ['success' => true];
    }

    public function connectVpn($vpnId) {
        $vpns = $this->getVpnList();
        $vpn = null;

        foreach ($vpns as $v) {
            if ($v['id'] === $vpnId) {
                $vpn = $v;
                break;
            }
        }

        if (!$vpn) {
            throw new Exception("VPN not found: $vpnId");
        }

        $this->disconnectVpn();

        $result = $this->executeCommand("pon $vpnId");

        if ($result['success']) {
            sleep(5);

            $status = $this->getVpnStatus($vpnId);
            if ($status['connected']) {
                $setupResult = $this->setupBridgeRouting();

                if ($setupResult) {
                    if (is_writable(dirname(ACTIVE_VPN_FILE))) {
                        file_put_contents(ACTIVE_VPN_FILE, $vpnId);
                    }

                    $vpn['last_connected'] = date('Y-m-d H:i:s');
                    $this->saveVpn($vpn);

                    $this->log("Successfully connected VPN: {$vpn['name']}");

                    return [
                        'success' => true,
                        'message' => "Connected to {$vpn['name']}",
                        'vpn_info' => $status
                    ];
                } else {
                    $this->log("VPN connected but routing setup failed: {$vpn['name']}", 'ERROR');
                    return [
                        'success' => false,
                        'message' => "VPN connected but routing setup failed"
                    ];
                }
            } else {
                $this->log("VPN connection failed: {$vpn['name']}", 'ERROR');
                return [
                    'success' => false,
                    'message' => "Failed to establish connection to {$vpn['name']}"
                ];
            }
        } else {
            $this->log("Failed to connect VPN: {$vpn['name']} - {$result['output']}", 'ERROR');
            return [
                'success' => false,
                'message' => "Connection failed: " . $result['output']
            ];
        }
    }

    public function disconnectVpn() {
        $activeVpn = $this->getActiveVpn();

        if (!$activeVpn) {
            return ['success' => true, 'message' => 'No active VPN to disconnect'];
        }

        $this->clearBridgeRouting();
        $result = $this->executeCommand("poff $activeVpn");

        if (file_exists(ACTIVE_VPN_FILE)) {
            unlink(ACTIVE_VPN_FILE);
        }

        sleep(2);

        $this->log("Disconnected VPN: $activeVpn");

        return [
            'success' => true,
            'message' => "Disconnected from VPN"
        ];
    }

    private function setupBridgeRouting() {
        $this->log("Setting up bridge routing");

        $this->clearBridgeRouting();

        sleep(2);

        $l2tpInfo = $this->detectL2tpNetwork();
        $l2tpNetwork = $l2tpInfo['network'];

        $pptpGateway = $this->getPptpGateway();
        if (!$pptpGateway) {
            $this->log("Cannot detect PPTP gateway - routing setup failed", 'ERROR');
            return false;
        }

        $this->log("Configuring VPN routing: L2TP ($l2tpNetwork) → PPTP ($pptpGateway)");

        $this->executeCommand("echo 1 > /proc/sys/net/ipv4/ip_forward");

        $this->executeCommand("iptables -t nat -D POSTROUTING -o enp6s18 -j MASQUERADE 2>/dev/null || true");

        $commands = [
            "iptables -t nat -A POSTROUTING -s $l2tpNetwork -o ppp1 -j MASQUERADE",
            "iptables -A FORWARD -i ppp0 -o ppp1 -j ACCEPT",
            "iptables -A FORWARD -i ppp1 -o ppp0 -j ACCEPT",
        ];

        foreach ($commands as $command) {
            $result = $this->executeCommand($command);
            if (!$result['success']) {
                $this->log("Failed to execute: $command - " . $result['output'], 'ERROR');
            }
        }

        $policyCommands = [
            "ip route add default via $pptpGateway dev ppp1 table 200 2>/dev/null || true",
            "ip rule add from $l2tpNetwork table 200 priority 200 2>/dev/null || true"
        ];

        foreach ($policyCommands as $command) {
            $result = $this->executeCommand($command);
            if (!$result['success']) {
                $this->log("Failed policy routing: $command - " . $result['output'], 'ERROR');
            }
        }

        $this->executeCommand("ip rule show");
        $this->executeCommand("ip route show table 200");

        $this->log("VPN routing configured: L2TP ($l2tpNetwork) → PPTP (ppp1) → $pptpGateway");
        return true;
    }

    private function clearBridgeRouting() {
        $this->log("Clearing VPN bridge routing");

        $l2tpInfo = $this->detectL2tpNetwork();
        $l2tpNetwork = $l2tpInfo['network'];

        $commands = [
            "iptables -t nat -D POSTROUTING -s $l2tpNetwork -o ppp1 -j MASQUERADE 2>/dev/null || true",
            "iptables -D FORWARD -i ppp0 -o ppp1 -j ACCEPT 2>/dev/null || true",
            "iptables -D FORWARD -i ppp1 -o ppp0 -j ACCEPT 2>/dev/null || true",
        ];

        foreach ($commands as $command) {
            $this->executeCommand($command);
        }

        $policyCommands = [
            "ip rule del from $l2tpNetwork table 200 priority 200 2>/dev/null || true",
            "ip route flush table 200 2>/dev/null || true",
        ];

        foreach ($policyCommands as $command) {
            $this->executeCommand($command);
        }

        $restoreCommands = [
            "iptables -t nat -A POSTROUTING -o enp6s18 -j MASQUERADE"
        ];

        foreach ($restoreCommands as $command) {
            $result = $this->executeCommand($command);
            if ($result['success']) {
                $this->log("Restored normal internet routing");
            } else {
                $this->log("Failed to restore internet: $command", 'ERROR');
            }
        }

        $this->log("VPN routing cleared, normal internet restored");
    }

    private function getActiveVpn() {
        if (file_exists(ACTIVE_VPN_FILE) && is_readable(ACTIVE_VPN_FILE)) {
            return trim(file_get_contents(ACTIVE_VPN_FILE));
        }
        return null;
    }

    private function getVpnStatus($vpnId) {
        $status = [
            'connected' => false,
            'interface' => null,
            'local_ip' => null,
            'remote_ip' => null,
            'remote_network' => null,
            'uptime' => null,
            'bytes_received' => 0,
            'bytes_sent' => 0
        ];

        $ifconfig = $this->executeCommand("ifconfig ppp1 2>/dev/null");
        if ($ifconfig['success'] && strpos($ifconfig['output'], 'ppp1') !== false) {
            $status['connected'] = true;
            $status['interface'] = 'ppp1';

            if (preg_match('/inet (\d+\.\d+\.\d+\.\d+)/', $ifconfig['output'], $matches)) {
                $status['local_ip'] = $matches[1];
            }
            if (preg_match('/P-t-P:(\d+\.\d+\.\d+\.\d+)/', $ifconfig['output'], $matches)) {
                $status['remote_ip'] = $matches[1];
            }

            $routes = $this->executeCommand("ip route | grep ppp1");
            if ($routes['success']) {
                if (preg_match('/(\d+\.\d+\.\d+\.\d+\/\d+).*dev ppp1/', $routes['output'], $matches)) {
                    $status['remote_network'] = $matches[1];
                }
            }

            $rxFile = "/sys/class/net/ppp1/statistics/rx_bytes";
            $txFile = "/sys/class/net/ppp1/statistics/tx_bytes";

            if (file_exists($rxFile)) {
                $status['bytes_received'] = intval(file_get_contents($rxFile));
            }
            if (file_exists($txFile)) {
                $status['bytes_sent'] = intval(file_get_contents($txFile));
            }

            $uptime = $this->executeCommand("ps -o etime= -C pppd | head -1");
            if ($uptime['success']) {
                $status['uptime'] = trim($uptime['output']);
            }
        }

        return $status;
    }

    private function createPptpConfig($vpn) {
        $config = "pty \"pptp {$vpn['server']} --nolaunchpppd\"\n";
        $config .= "name {$vpn['username']}\n";
        $config .= "password {$vpn['password']}\n";
        $config .= "remotename {$vpn['id']}\n";
        $config .= "require-mppe-128\n";
        $config .= "file /etc/ppp/options.pptp\n";
        $config .= "ipparam {$vpn['id']}\n";
        $config .= "nodefaultroute\n";
        $config .= "replacedefaultroute\n";
        $config .= "usepeerdns\n";

        $peerFile = PPP_PEERS_DIR . "/{$vpn['id']}";

        if (!is_dir(PPP_PEERS_DIR)) {
            mkdir(PPP_PEERS_DIR, 0755, true);
        }

        if (is_writable(PPP_PEERS_DIR) || is_writable($peerFile)) {
            file_put_contents($peerFile, $config);
        } else {
            $this->log("Cannot write to PPP peers directory: " . PPP_PEERS_DIR, 'ERROR');
        }

        if (!file_exists('/etc/ppp/options.pptp')) {
            $options = "lock\nnoauth\nnobsdcomp\nnodeflate\nrequire-mppe-128\n";
            if (is_writable('/etc/ppp/')) {
                file_put_contents('/etc/ppp/options.pptp', $options);
            }
        }
    }

    private function saveVpn($vpn) {
        $vpns = $this->getVpnList();

        $found = false;
        foreach ($vpns as &$existingVpn) {
            if ($existingVpn['id'] === $vpn['id']) {
                $existingVpn = $vpn;
                $found = true;
                break;
            }
        }

        if (!$found) {
            $vpns[] = $vpn;
        }

        $this->saveVpnList($vpns);
    }

    private function saveVpnList($vpns) {
        $configFile = VPN_CONFIG_DIR . '/vpn_list.json';

        if (is_writable(VPN_CONFIG_DIR) || is_writable($configFile)) {
            file_put_contents($configFile, json_encode($vpns, JSON_PRETTY_PRINT));
            if (file_exists($configFile)) {
                chmod($configFile, 0644);
            }
        } else {
            $this->log("Cannot write to VPN config file: " . $configFile, 'ERROR');
            throw new Exception("Cannot save VPN configuration - permission denied");
        }
    }

    public function getLogs($lines = 100) {
        if (!file_exists(LOG_FILE) || !is_readable(LOG_FILE)) {
            return [];
        }

        $command = "tail -n $lines " . LOG_FILE;
        $result = $this->executeCommand($command);

        if ($result['success']) {
            return array_values(array_filter(explode("\n", $result['output'])));
        }

        return [];
    }

    public function getSystemStatus() {
        $status = [
            'main_l2tp' => false,
            'active_vpn' => null,
            'ppp_interface' => false,
            'bridge_routing' => false,
            'system_load' => 0,
            'memory_usage' => 0,
            'uptime' => '',
            'l2tp_network' => null
        ];

        $l2tpStatus = $this->executeCommand("systemctl is-active xl2tpd.service");
        $status['main_l2tp'] = trim($l2tpStatus['output']) === 'active';

        $status['active_vpn'] = $this->getActiveVpn();

        $pppCheck = $this->executeCommand("ifconfig ppp1 2>/dev/null");
        $status['ppp_interface'] = $pppCheck['success'];

        $l2tpInfo = $this->detectL2tpNetwork();
        $status['l2tp_network'] = $l2tpInfo['network'];

        $routeCheck = $this->executeCommand("iptables -t nat -L POSTROUTING -n | grep 'ppp1.*MASQUERADE'");
        $status['bridge_routing'] = $routeCheck['success'] && !empty(trim($routeCheck['output']));

        if (file_exists('/proc/loadavg')) {
            $loadavg = file_get_contents('/proc/loadavg');
            $status['system_load'] = floatval(explode(' ', $loadavg)[0]);
        }

        if (file_exists('/proc/meminfo')) {
            $meminfo = file_get_contents('/proc/meminfo');
            if (preg_match('/MemTotal:\s+(\d+) kB/', $meminfo, $matches)) {
                $total = intval($matches[1]);
                if (preg_match('/MemAvailable:\s+(\d+) kB/', $meminfo, $matches)) {
                    $available = intval($matches[1]);
                    $status['memory_usage'] = round((($total - $available) / $total) * 100, 1);
                }
            }
        }

        if (file_exists('/proc/uptime')) {
            $uptime = file_get_contents('/proc/uptime');
            $uptimeSeconds = floatval(explode(' ', $uptime)[0]);
            $status['uptime'] = $this->formatUptime($uptimeSeconds);
        }

        return $status;
    }

    public function debugRouting() {
        $debug = [
            'timestamp' => date('Y-m-d H:i:s'),
            'summary' => [],
            'interfaces' => [],
            'routing' => [],
            'iptables' => [],
            'l2tp_detection' => [],
            'remote_networks' => [],
            'pptp_gateway' => null,
            'files' => [],
            'processes' => [],
            'services' => [],
            'system' => [],
            'connectivity' => [],
            'stats' => [],
            'tests' => [],
            'raw_commands' => []
        ];

        $debug['summary']['l2tp_active'] = $this->executeCommand("ip addr show ppp0 2>/dev/null | grep -q 'inet' && echo 'YES' || echo 'NO'");
        $debug['summary']['pptp_active'] = $this->executeCommand("ip addr show ppp1 2>/dev/null | grep -q 'inet' && echo 'YES' || echo 'NO'");
        $debug['summary']['ip_forwarding'] = $this->executeCommand("cat /proc/sys/net/ipv4/ip_forward");
        $debug['summary']['active_vpn_file'] = file_exists(ACTIVE_VPN_FILE) ? trim(file_get_contents(ACTIVE_VPN_FILE)) : 'NONE';

        $debug['pptp_gateway'] = $this->getPptpGateway();

        $debug['interfaces']['all_interfaces'] = $this->executeCommand("ip addr show");
        $debug['interfaces']['ppp0_detailed'] = $this->executeCommand("ip addr show ppp0 2>/dev/null");
        $debug['interfaces']['ppp1_detailed'] = $this->executeCommand("ip addr show ppp1 2>/dev/null");
        $debug['interfaces']['ifconfig_ppp0'] = $this->executeCommand("ifconfig ppp0 2>/dev/null");
        $debug['interfaces']['ifconfig_ppp1'] = $this->executeCommand("ifconfig ppp1 2>/dev/null");

        $debug['routing']['main_table'] = $this->executeCommand("ip route show");
        $debug['routing']['table_200'] = $this->executeCommand("ip route show table 200 2>/dev/null");
        $debug['routing']['rules'] = $this->executeCommand("ip rule show");

        $debug['iptables']['nat_postrouting'] = $this->executeCommand("iptables -t nat -L POSTROUTING -n -v");
        $debug['iptables']['filter_forward'] = $this->executeCommand("iptables -L FORWARD -n -v");

        $l2tpInfo = $this->detectL2tpNetwork();
        $debug['l2tp_detection']['detected_network'] = $l2tpInfo;

        $debug['remote_networks']['detected'] = $this->getRemoteNetworks();

        $debug['processes']['all_pppd'] = $this->executeCommand("ps aux | grep pppd");
        $debug['processes']['all_pptp'] = $this->executeCommand("ps aux | grep pptp");

        $debug['services']['xl2tpd_status'] = $this->executeCommand("systemctl is-active xl2tpd.service");

        $debug['system']['ip_forward'] = $this->executeCommand("cat /proc/sys/net/ipv4/ip_forward");

        if (file_exists(ACTIVE_VPN_FILE)) {
            $debug['files']['active_vpn'] = trim(file_get_contents(ACTIVE_VPN_FILE));
        }

        $debug['connectivity']['ping_l2tp_client'] = $this->executeCommand("ping -c 2 -W 2 10.0.20.10 2>/dev/null");

        $pptpGateway = $debug['pptp_gateway'];
        if ($pptpGateway) {
            $debug['connectivity']['ping_pptp_gateway'] = $this->executeCommand("ping -c 2 -W 2 $pptpGateway 2>/dev/null");
        }

        if (file_exists('/sys/class/net/ppp0/statistics/rx_bytes')) {
            $debug['stats']['ppp0_rx_bytes'] = trim(file_get_contents('/sys/class/net/ppp0/statistics/rx_bytes'));
            $debug['stats']['ppp0_tx_bytes'] = trim(file_get_contents('/sys/class/net/ppp0/statistics/tx_bytes'));
        }
        if (file_exists('/sys/class/net/ppp1/statistics/rx_bytes')) {
            $debug['stats']['ppp1_rx_bytes'] = trim(file_get_contents('/sys/class/net/ppp1/statistics/rx_bytes'));
            $debug['stats']['ppp1_tx_bytes'] = trim(file_get_contents('/sys/class/net/ppp1/statistics/tx_bytes'));
        }

        $l2tpNetwork = $l2tpInfo['network'];

        $debug['tests']['interfaces_up'] = [
            'ppp0' => $this->executeCommand("ip link show ppp0 2>/dev/null | grep -q 'state UP' && echo 'UP' || echo 'DOWN'"),
            'ppp1' => $this->executeCommand("ip link show ppp1 2>/dev/null | grep -q 'state UP' && echo 'UP' || echo 'DOWN'")
        ];

        $debug['tests']['ip_forwarding_enabled'] = $this->executeCommand("[ $(cat /proc/sys/net/ipv4/ip_forward) = '1' ] && echo 'ENABLED' || echo 'DISABLED'");

        $debug['tests']['iptables_rules_exist'] = [
            'nat_masquerade' => $this->executeCommand("iptables -t nat -C POSTROUTING -s $l2tpNetwork -o ppp1 -j MASQUERADE 2>&1 && echo 'EXISTS' || echo 'MISSING'"),
            'forward_ppp0_to_ppp1' => $this->executeCommand("iptables -C FORWARD -i ppp0 -o ppp1 -j ACCEPT 2>&1 && echo 'EXISTS' || echo 'MISSING'"),
            'forward_ppp1_to_ppp0' => $this->executeCommand("iptables -C FORWARD -i ppp1 -o ppp0 -j ACCEPT 2>&1 && echo 'EXISTS' || echo 'MISSING'")
        ];

        $debug['tests']['routing_rules_exist'] = [
            'table_200_default' => $this->executeCommand("ip route show table 200 | grep -q 'default.*ppp1' && echo 'EXISTS' || echo 'MISSING'"),
            'rule_from_l2tp' => $this->executeCommand("ip rule show | grep -q '$l2tpNetwork.*table 200' && echo 'EXISTS' || echo 'MISSING'")
        ];

        return $debug;
    }

    public function testRouting() {
        $test = [
            'timestamp' => date('Y-m-d H:i:s'),
            'tests' => []
        ];

        $test['tests']['interfaces_up'] = [
            'ppp0' => $this->executeCommand("ip link show ppp0 | grep 'state UP'"),
            'ppp1' => $this->executeCommand("ip link show ppp1 | grep 'state UP'")
        ];

        $test['tests']['ip_forwarding'] = $this->executeCommand("cat /proc/sys/net/ipv4/ip_forward");

        $l2tpInfo = $this->detectL2tpNetwork();
        $l2tpNetwork = $l2tpInfo['network'];

        $test['tests']['iptables_rules'] = [
            'nat_rule' => $this->executeCommand("iptables -t nat -C POSTROUTING -s $l2tpNetwork -o ppp1 -j MASQUERADE 2>&1"),
            'forward_rule1' => $this->executeCommand("iptables -C FORWARD -i ppp0 -o ppp1 -j ACCEPT 2>&1"),
            'forward_rule2' => $this->executeCommand("iptables -C FORWARD -i ppp1 -o ppp0 -j ACCEPT 2>&1")
        ];

        $test['tests']['routing_tables'] = [
            'default_via_ppp1' => $this->executeCommand("ip route show table 200 | grep 'default.*ppp1'"),
            'rule_exists' => $this->executeCommand("ip rule show | grep '$l2tpNetwork.*table 200'")
        ];

        $pptpGateway = $this->getPptpGateway();
        $test['tests']['connectivity'] = [
            'ubuntu_to_l2tp_client' => $this->executeCommand("ping -c 2 -W 2 10.0.20.10 2>/dev/null"),
            'ubuntu_to_pptp_gateway' => $pptpGateway ?
                $this->executeCommand("ping -c 2 -W 2 $pptpGateway 2>/dev/null") :
                ['success' => false, 'output' => 'No PPTP gateway detected']
        ];

        return $test;
    }

    public function resetRouting() {
        $this->log("Manual routing reset requested");

        $this->clearBridgeRouting();
        sleep(1);

        $result = $this->setupBridgeRouting();

        return [
            'success' => $result,
            'message' => $result ? 'Routing has been reset successfully' : 'Routing reset failed',
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    private function formatUptime($seconds) {
        $days = floor($seconds / 86400);
        $hours = floor(($seconds % 86400) / 3600);
        $minutes = floor(($seconds % 3600) / 60);

        if ($days > 0) {
            return "{$days}d {$hours}h {$minutes}m";
        } elseif ($hours > 0) {
            return "{$hours}h {$minutes}m";
        } else {
            return "{$minutes}m";
        }
    }
}

try {
    $vpnBridge = new VPNBridge();
    $method = $_SERVER['REQUEST_METHOD'];
    $action = $_GET['action'] ?? '';

    switch ($action) {
        case 'vpns':
            if ($method === 'GET') {
                echo json_encode(['success' => true, 'data' => $vpnBridge->getVpnList()]);
            } else if ($method === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                $result = $vpnBridge->addVpn($data);
                echo json_encode($result);
            }
            break;

        case 'vpn':
            $vpnId = $_GET['id'] ?? '';
            if ($method === 'PUT') {
                $data = json_decode(file_get_contents('php://input'), true);
                $result = $vpnBridge->updateVpn($vpnId, $data);
                echo json_encode($result);
            } else if ($method === 'DELETE') {
                $result = $vpnBridge->deleteVpn($vpnId);
                echo json_encode($result);
            }
            break;

        case 'connect':
            $vpnId = $_GET['id'] ?? '';
            $result = $vpnBridge->connectVpn($vpnId);
            echo json_encode($result);
            break;

        case 'disconnect':
            $result = $vpnBridge->disconnectVpn();
            echo json_encode($result);
            break;

        case 'logs':
            $lines = intval($_GET['lines'] ?? 100);
            $logs = $vpnBridge->getLogs($lines);
            echo json_encode(['success' => true, 'data' => $logs]);
            break;

        case 'status':
            $status = $vpnBridge->getSystemStatus();
            echo json_encode(['success' => true, 'data' => $status]);
            break;

        case 'debug':
            $debug = $vpnBridge->debugRouting();
            echo json_encode(['success' => true, 'data' => $debug]);
            break;

        case 'test':
            $test = $vpnBridge->testRouting();
            echo json_encode(['success' => true, 'data' => $test]);
            break;

        case 'reset':
            $reset = $vpnBridge->resetRouting();
            echo json_encode($reset);
            break;

        default:
            echo json_encode(['success' => false, 'error' => 'Unknown action: ' . $action]);
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
?>
PHPEOF

# Create frontend placeholder
echo -e "${YELLOW}🌐 Creating web interface...${NC}"
cat > /var/www/html/vpn-bridge/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN Bridge Manager</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <style>
        :root {
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --primary-light: #dbeafe;
            --secondary: #7c3aed;
            --success: #059669;
            --success-light: #d1fae5;
            --warning: #d97706;
            --warning-light: #fef3c7;
            --error: #dc2626;
            --error-light: #fee2e2;
            --gray-50: #f8fafc;
            --gray-100: #f1f5f9;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e1;
            --gray-400: #94a3b8;
            --gray-500: #64748b;
            --gray-600: #475569;
            --gray-700: #334155;
            --gray-800: #1e293b;
            --gray-900: #0f172a;
            --white: #ffffff;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
        }

        .language-selector {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: var(--gray-100);
            border-radius: 0.5rem;
            padding: 0.25rem;
            border: 1px solid var(--gray-200);
        }

        .language-btn {
            padding: 0.375rem 0.75rem;
            border: none;
            background: transparent;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            color: var(--gray-600);
        }

        .language-btn.active {
            background: var(--white);
            color: var(--primary);
            box-shadow: var(--shadow-sm);
        }

        .language-btn:hover:not(.active) {
            color: var(--gray-900);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--gray-50);
            color: var(--gray-900);
            line-height: 1.6;
        }

        /* Header */
        .header {
            background: var(--white);
            border-bottom: 1px solid var(--gray-200);
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(10px);
            box-shadow: var(--shadow-sm);
        }

        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary);
        }

        .logo .material-icons {
            font-size: 2rem;
            background: var(--primary);
            color: var(--white);
            padding: 0.5rem;
            border-radius: 0.75rem;
        }

        .header-subtitle {
            color: var(--gray-500);
            font-size: 0.875rem;
            font-weight: 500;
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }

        .current-time {
            text-align: right;
        }

        .time-label {
            font-size: 0.75rem;
            color: var(--gray-500);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }

        .time-value {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--gray-900);
            font-variant-numeric: tabular-nums;
        }

        /* Container */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }

        /* Stack panels */
        .stack-panel {
            background: var(--white);
            border-radius: 1rem;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--gray-200);
        }

        .panel-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--gray-200);
        }

        .panel-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--gray-900);
        }

        .panel-icon {
            background: var(--primary-light);
            color: var(--primary);
            padding: 0.5rem;
            border-radius: 0.5rem;
            font-size: 1.25rem !important;
        }

        /* System Status Panel */
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
        }

        .status-item {
            background: var(--gray-50);
            padding: 1.5rem;
            border-radius: 0.75rem;
            border: 1px solid var(--gray-200);
            transition: all 0.2s ease;
        }

        .status-item:hover {
            background: var(--white);
            box-shadow: var(--shadow-md);
        }

        .status-item-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.75rem;
        }

        .status-label {
            font-size: 0.875rem;
            color: var(--gray-600);
            font-weight: 500;
        }

        .status-chip {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }

        .status-chip.active {
            background: var(--success-light);
            color: var(--success);
        }

        .status-chip.inactive {
            background: var(--error-light);
            color: var(--error);
        }

        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
        }

        .status-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--gray-900);
        }

        /* VPN Management Panel */
        .management-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 0.5rem;
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            position: relative;
            overflow: hidden;
        }

        .btn-primary {
            background: var(--primary);
            color: var(--white);
            box-shadow: var(--shadow-sm);
        }

        .btn-primary:hover {
            background: var(--primary-hover);
            box-shadow: var(--shadow-md);
            transform: translateY(-1px);
        }

        .btn-success {
            background: var(--success);
            color: var(--white);
            box-shadow: var(--shadow-sm);
        }

        .btn-success:hover {
            background: #047857;
            box-shadow: var(--shadow-md);
            transform: translateY(-1px);
        }

        .btn-danger {
            background: var(--error);
            color: var(--white);
            box-shadow: var(--shadow-sm);
        }

        .btn-danger:hover {
            background: #b91c1c;
            box-shadow: var(--shadow-md);
            transform: translateY(-1px);
        }

        .btn-outline {
            background: var(--white);
            color: var(--gray-700);
            border: 1px solid var(--gray-300);
        }

        .btn-outline:hover {
            background: var(--gray-50);
            border-color: var(--primary);
            color: var(--primary);
        }

        /* VPN Cards Grid */
        .vpn-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 1.5rem;
        }

        .vpn-card {
            background: var(--white);
            border: 1px solid var(--gray-200);
            border-radius: 0.75rem;
            padding: 1.5rem;
            transition: all 0.2s ease;
            position: relative;
        }

        .vpn-card:hover {
            box-shadow: var(--shadow-lg);
            transform: translateY(-2px);
            border-color: var(--primary);
        }

        .vpn-card::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
            background: var(--gray-300);
            border-radius: 0.25rem 0 0 0.25rem;
            transition: background-color 0.2s ease;
        }

        .vpn-card.active::before {
            background: var(--success);
        }

        .vpn-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }

        .vpn-name {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--gray-900);
            margin-bottom: 0.25rem;
        }

        .vpn-server {
            font-size: 0.875rem;
            color: var(--gray-600);
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
        }

        .vpn-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin: 1.5rem 0;
            padding: 1rem;
            background: var(--gray-50);
            border-radius: 0.5rem;
        }

        .vpn-detail {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .vpn-detail-label {
            font-size: 0.75rem;
            color: var(--gray-500);
            text-transform: uppercase;
            letter-spacing: 0.025em;
            font-weight: 600;
        }

        .vpn-detail-value {
            font-size: 0.875rem;
            color: var(--gray-900);
            font-weight: 500;
        }

        .vpn-description {
            color: var(--gray-600);
            font-size: 0.875rem;
            margin-bottom: 1.5rem;
            font-style: italic;
        }

        .vpn-actions {
            display: flex;
            gap: 0.75rem;
        }

        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.8125rem;
        }

        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 3rem 1.5rem;
            color: var(--gray-500);
        }

        .empty-state .material-icons {
            font-size: 4rem;
            margin-bottom: 1rem;
            opacity: 0.3;
        }

        .empty-state-title {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: var(--gray-700);
        }

        .empty-state-description {
            font-size: 0.875rem;
        }

        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(4px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }

        .modal.show {
            display: flex;
        }

        .modal-content {
            background: var(--white);
            border-radius: 1rem;
            padding: 2rem;
            max-width: 500px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: var(--shadow-xl);
            animation: modalSlideIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        @keyframes modalSlideIn {
            from {
                opacity: 0;
                transform: scale(0.95) translateY(20px);
            }
            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }

        .modal-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--gray-200);
        }

        .modal-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--gray-900);
        }

        .input-group {
            margin-bottom: 1.5rem;
        }

        .input-label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--gray-700);
        }

        .input-field {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--gray-300);
            border-radius: 0.5rem;
            font-size: 1rem;
            background: var(--white);
            color: var(--gray-900);
            transition: all 0.2s ease;
        }

        .input-field:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .input-field::placeholder {
            color: var(--gray-400);
        }

        .logs-container {
            background: var(--gray-900);
            color: var(--gray-100);
            border-radius: 0.5rem;
            padding: 1.5rem;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.875rem;
            max-height: 400px;
            overflow-y: auto;
            margin-top: 1rem;
            line-height: 1.5;
        }

        .logs-container::-webkit-scrollbar {
            width: 8px;
        }

        .logs-container::-webkit-scrollbar-track {
            background: var(--gray-700);
            border-radius: 4px;
        }

        .logs-container::-webkit-scrollbar-thumb {
            background: var(--gray-500);
            border-radius: 4px;
        }

        /* Notification */
        .notification {
            position: fixed;
            top: 6rem;
            right: 1.5rem;
            padding: 1rem 1.25rem;
            border-radius: 0.75rem;
            color: var(--white);
            font-weight: 600;
            z-index: 1001;
            transform: translateX(400px);
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: var(--shadow-lg);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            max-width: 320px;
        }

        .notification.show {
            transform: translateX(0);
        }

        .notification.success {
            background: var(--success);
        }

        .notification.error {
            background: var(--error);
        }

        /* Responsive */
        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }

            .header-right {
                justify-content: center;
            }

            .container {
                padding: 1rem;
            }

            .stack-panel {
                padding: 1.5rem;
            }

            .status-grid {
                grid-template-columns: 1fr;
            }

            .vpn-grid {
                grid-template-columns: 1fr;
            }

            .vpn-details {
                grid-template-columns: 1fr;
            }

            .vpn-actions {
                flex-direction: column;
            }

            .management-actions {
                flex-direction: column;
            }

            .modal-content {
                margin: 1rem;
                padding: 1.5rem;
            }
        }

        @media (max-width: 480px) {
            .btn {
                justify-content: center;
                width: 100%;
            }

            .vpn-card-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.75rem;
            }
        }

        /* Animations */
        .refresh-indicator {
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .loading {
            opacity: 0.6;
            pointer-events: none;
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <div class="header-content">
            <div class="header-left">
                <div class="logo">
                    <span class="material-icons">router</span>
                    <div>
                        <div>VPN Bridge Manager</div>
                        <div class="header-subtitle" data-lang="subtitle">L2TP ↔ PPTP Bridge Management</div>
                    </div>
                </div>
            </div>
            <div class="header-right">
                <div class="language-selector">
                    <button class="language-btn active" onclick="setLanguage('en')" id="lang-en">EN</button>
                    <button class="language-btn" onclick="setLanguage('pl')" id="lang-pl">PL</button>
                </div>
                <div class="current-time">
                    <div class="time-label" data-lang="current-time">Current Time</div>
                    <div class="time-value" id="currentTime">--:--:--</div>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <div class="container">
        <!-- System Status Panel -->
        <div class="stack-panel">
            <div class="panel-header">
                <span class="material-icons panel-icon">monitor_heart</span>
                <h2 class="panel-title" data-lang="system-status">System Status</h2>
                <button class="btn btn-outline btn-sm" onclick="refreshStatus()" style="margin-left: auto;">
                    <span class="material-icons" style="font-size: 1rem;" id="statusRefreshIcon">refresh</span>
                    <span data-lang="refresh">Refresh</span>
                </button>
            </div>

            <div class="status-grid" id="systemStatusGrid">
                <div class="status-item">
                    <div class="status-item-header">
                        <span class="status-label" data-lang="main-status">Main Status</span>
                        <div class="status-chip" id="systemStatusChip">
                            <div class="status-dot"></div>
                            <span data-lang="checking">Checking...</span>
                        </div>
                    </div>
                    <div class="status-value" id="mainStatus">System</div>
                </div>

                <div class="status-item">
                    <div class="status-item-header">
                        <span class="status-label" data-lang="l2tp-server">L2TP Server</span>
                    </div>
                    <div class="status-value" id="l2tpStatus">-</div>
                </div>

                <div class="status-item">
                    <div class="status-item-header">
                        <span class="status-label" data-lang="active-vpn">Active VPN</span>
                    </div>
                    <div class="status-value" id="activeVpn" data-lang="none">None</div>
                </div>

                <div class="status-item">
                    <div class="status-item-header">
                        <span class="status-label" data-lang="load">Load</span>
                    </div>
                    <div class="status-value" id="systemLoad">-</div>
                </div>

                <div class="status-item">
                    <div class="status-item-header">
                        <span class="status-label" data-lang="memory">Memory</span>
                    </div>
                    <div class="status-value" id="memoryUsage">-</div>
                </div>
            </div>
        </div>

        <!-- VPN Management Panel -->
        <div class="stack-panel">
            <div class="panel-header">
                <span class="material-icons panel-icon">vpn_key</span>
                <h2 class="panel-title" data-lang="vpn-management">VPN Management</h2>
                <div style="margin-left: auto; display: flex; gap: 0.75rem;">
                    <button class="btn btn-primary btn-sm" onclick="showAddVpnModal()">
                        <span class="material-icons" style="font-size: 1rem;">add</span>
                        <span data-lang="add-vpn">Add VPN</span>
                    </button>
                    <button class="btn btn-outline btn-sm" onclick="refreshVpnList()">
                        <span class="material-icons" style="font-size: 1rem;" id="refreshIcon">refresh</span>
                        <span data-lang="refresh-list">Refresh List</span>
                    </button>
                </div>
            </div>

            <div class="vpn-grid" id="vpnGrid">
                <!-- VPN cards will be loaded here -->
                <div class="empty-state">
                    <span class="material-icons">vpn_key_off</span>
                    <div class="empty-state-title" data-lang="loading-vpns">Loading VPN connections...</div>
                    <div class="empty-state-description" data-lang="please-wait">Please wait</div>
                </div>
            </div>
        </div>

        <!-- System Logs Panel -->
        <div class="stack-panel">
            <div class="panel-header">
                <span class="material-icons panel-icon">terminal</span>
                <h2 class="panel-title" data-lang="system-logs">System Logs</h2>
                <button class="btn btn-outline btn-sm" onclick="refreshLogs()" style="margin-left: auto;">
                    <span class="material-icons" style="font-size: 1rem;" id="logsRefreshIcon">refresh</span>
                    <span data-lang="refresh">Refresh</span>
                </button>
            </div>

            <div class="logs-container" id="logsContent">
                <pre data-lang="loading-logs">Loading logs...</pre>
            </div>
        </div>
    </div>

    <!-- Add VPN Modal -->
    <div class="modal" id="addVpnModal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="material-icons panel-icon">add_circle</span>
                <div class="modal-title" data-lang="add-new-vpn">Add New VPN</div>
            </div>
            <form id="addVpnForm">
                <div class="input-group">
                    <label class="input-label" for="vpnName" data-lang="vpn-name">VPN Name</label>
                    <input type="text" id="vpnName" class="input-field" required data-placeholder="vpn-name-placeholder">
                </div>
                <div class="input-group">
                    <label class="input-label" for="vpnServer" data-lang="pptp-server">PPTP Server</label>
                    <input type="text" id="vpnServer" class="input-field" required placeholder="vpn.example.com">
                </div>
                <div class="input-group">
                    <label class="input-label" for="vpnUsername" data-lang="username">Username</label>
                    <input type="text" id="vpnUsername" class="input-field" required placeholder="username">
                </div>
                <div class="input-group">
                    <label class="input-label" for="vpnPassword" data-lang="password">Password</label>
                    <input type="password" id="vpnPassword" class="input-field" required placeholder="password">
                </div>
                <div class="input-group">
                    <label class="input-label" for="vpnDescription" data-lang="description-optional">Description (optional)</label>
                    <input type="text" id="vpnDescription" class="input-field" data-placeholder="description-placeholder">
                </div>
                <div class="management-actions" style="margin-top: 2rem; margin-bottom: 0;">
                    <button type="submit" class="btn btn-success">
                        <span class="material-icons">save</span>
                        <span data-lang="save-vpn">Save VPN</span>
                    </button>
                    <button type="button" class="btn btn-outline" onclick="closeModal('addVpnModal')">
                        <span class="material-icons">close</span>
                        <span data-lang="cancel">Cancel</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
        let vpnList = [];
        let systemStatus = {};
        let currentLanguage = 'en';

        // Language translations
        const translations = {
            en: {
                'current-time': 'Current Time',
                'subtitle': 'L2TP ↔ PPTP Bridge Management',
                'system-status': 'System Status',
                'refresh': 'Refresh',
                'main-status': 'Main Status',
                'checking': 'Checking...',
                'l2tp-server': 'L2TP Server',
                'active-vpn': 'Active VPN',
                'none': 'None',
                'load': 'Load',
                'memory': 'Memory',
                'system-logs': 'System Logs',
                'vpn-management': 'VPN Management',
                'add-vpn': 'Add VPN',
                'refresh-list': 'Refresh List',
                'loading-vpns': 'Loading VPN connections...',
                'please-wait': 'Please wait',
                'no-vpns-configured': 'No VPNs configured',
                'add-first-vpn': 'Add your first VPN to get started',
                'error-loading-vpns': 'Error loading VPN list',
                'check-server-connection': 'Check server connection',
                'connected': 'Connected',
                'disconnected': 'Disconnected',
                'user': 'User',
                'created': 'Created',
                'last-connection': 'Last Connection',
                'never': 'Never',
                'status': 'Status',
                'active': 'Active',
                'inactive': 'Inactive',
                'operational': 'Operational',
                'bridge-active': 'Bridge Active',
                'bridge': 'Bridge',
                'connect': 'Connect',
                'disconnect': 'Disconnect',
                'delete': 'Delete',
                'add-new-vpn': 'Add New VPN',
                'vpn-name': 'VPN Name',
                'vpn-name-placeholder': 'e.g. Warsaw Office',
                'pptp-server': 'PPTP Server',
                'username': 'Username',
                'password': 'Password',
                'description-optional': 'Description (optional)',
                'description-placeholder': 'VPN connection description',
                'save-vpn': 'Save VPN',
                'cancel': 'Cancel',
                'system-logs': 'System Logs',
                'loading-logs': 'Loading logs...',
                'close': 'Close',
                'connecting': 'Connecting to VPN...',
                'error-connecting': '✗ Error connecting to VPN',
                'error-disconnecting': '✗ Error disconnecting VPN',
                'confirm-delete': 'Are you sure you want to delete this VPN?',
                'vpn-deleted': '✓ VPN has been deleted',
                'error-deleting': '✗ Error deleting VPN',
                'vpn-added': '✓ VPN has been added',
                'error-adding': '✗ Error adding VPN',
                'no-logs': 'No logs available',
                'error-loading-logs': '✗ Error loading logs',
                'api-error': 'API Error',
                'error': 'Error'
            },
            pl: {
                'current-time': 'Aktualny czas',
                'subtitle': 'Zarządzanie mostkiem L2TP ↔ PPTP',
                'system-status': 'Status Systemu',
                'refresh': 'Odśwież',
                'main-status': 'Status Główny',
                'checking': 'Sprawdzanie...',
                'l2tp-server': 'Serwer L2TP',
                'active-vpn': 'Aktywny VPN',
                'none': 'Brak',
                'load': 'Obciążenie',
                'memory': 'Pamięć',
                'system-logs': 'Logi systemu',
                'vpn-management': 'Zarządzanie VPN',
                'add-vpn': 'Dodaj VPN',
                'refresh-list': 'Odśwież listę',
                'loading-vpns': 'Ładowanie połączeń VPN...',
                'please-wait': 'Proszę czekać',
                'no-vpns-configured': 'Brak skonfigurowanych VPN-ów',
                'add-first-vpn': 'Dodaj pierwszy VPN aby rozpocząć',
                'error-loading-vpns': 'Błąd ładowania listy VPN',
                'check-server-connection': 'Sprawdź połączenie z serwerem',
                'connected': 'Połączony',
                'disconnected': 'Rozłączony',
                'user': 'Użytkownik',
                'created': 'Utworzony',
                'last-connection': 'Ostatnie połączenie',
                'never': 'Nigdy',
                'status': 'Status',
                'active': 'Aktywny',
                'inactive': 'Nieaktywny',
                'operational': 'Operacyjny',
                'bridge-active': 'Bridge aktywny',
                'bridge': 'Bridge',
                'connect': 'Połącz',
                'disconnect': 'Rozłącz',
                'delete': 'Usuń',
                'add-new-vpn': 'Dodaj nowy VPN',
                'vpn-name': 'Nazwa VPN',
                'vpn-name-placeholder': 'np. Biuro Warszawa',
                'pptp-server': 'Serwer PPTP',
                'username': 'Nazwa użytkownika',
                'password': 'Hasło',
                'description-optional': 'Opis (opcjonalny)',
                'description-placeholder': 'Opis połączenia VPN',
                'save-vpn': 'Zapisz VPN',
                'cancel': 'Anuluj',
                'system-logs': 'Logi systemu',
                'loading-logs': 'Ładowanie logów...',
                'close': 'Zamknij',
                'connecting': 'Łączenie z VPN...',
                'error-connecting': '✗ Błąd połączenia z VPN',
                'error-disconnecting': '✗ Błąd rozłączania VPN',
                'confirm-delete': 'Czy na pewno chcesz usunąć ten VPN?',
                'vpn-deleted': '✓ VPN został usunięty',
                'error-deleting': '✗ Błąd usuwania VPN',
                'vpn-added': '✓ VPN został dodany',
                'error-adding': '✗ Błąd dodawania VPN',
                'no-logs': 'Brak logów',
                'error-loading-logs': '✗ Błąd ładowania logów',
                'api-error': 'Błąd API',
                'error': 'Błąd'
            }
        };

        // Language functions
        function setLanguage(lang) {
            currentLanguage = lang;

            // Update language buttons
            document.querySelectorAll('.language-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            document.getElementById(`lang-${lang}`).classList.add('active');

            // Update all text elements
            document.querySelectorAll('[data-lang]').forEach(element => {
                const key = element.getAttribute('data-lang');
                if (translations[lang] && translations[lang][key]) {
                    element.textContent = translations[lang][key];
                }
            });

            // Update placeholders
            document.querySelectorAll('[data-placeholder]').forEach(element => {
                const key = element.getAttribute('data-placeholder');
                if (translations[lang] && translations[lang][key]) {
                    element.placeholder = translations[lang][key];
                }
            });

            // Re-render VPN list and system status to update dynamic content
            renderVpnList();
            renderSystemStatus();

            // Save language preference
            localStorage.setItem('vpn-manager-language', lang);
        }

        function t(key) {
            return translations[currentLanguage][key] || key;
        }

        // Update current time
        function updateCurrentTime() {
            const now = new Date();
            const timeString = now.toLocaleTimeString(currentLanguage === 'pl' ? 'pl-PL' : 'en-US', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            document.getElementById('currentTime').textContent = timeString;
        }

        // API calls
        async function apiCall(url, options = {}) {
            try {
                const response = await fetch(`/vpn-bridge/api.php${url}`, {
                    headers: {
                        'Content-Type': 'application/json',
                        ...options.headers
                    },
                    ...options
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }

                return await response.json();
            } catch (error) {
                console.error('API call failed:', error);
                showNotification(`${t('api-error')}: ${error.message}`, 'error');
                throw error;
            }
        }

        // Load VPN list
        async function loadVpnList() {
            try {
                const response = await apiCall('?action=vpns');
                if (response.success) {
                    vpnList = response.data;
                    renderVpnList();
                }
            } catch (error) {
                document.getElementById('vpnGrid').innerHTML = `
                    <div class="empty-state">
                        <span class="material-icons">error</span>
                        <div class="empty-state-title">${t('error-loading-vpns')}</div>
                        <div class="empty-state-description">${t('check-server-connection')}</div>
                    </div>
                `;
            }
        }

        // Load system status
        async function loadSystemStatus() {
            try {
                const response = await apiCall('?action=status');
                if (response.success) {
                    systemStatus = response.data;
                    renderSystemStatus();
                }
            } catch (error) {
                const chip = document.getElementById('systemStatusChip');
                chip.className = 'status-chip inactive';
                chip.innerHTML = `<div class="status-dot"></div><span>${t('error')}</span>`;
            }
        }

        // Render VPN list
        function renderVpnList() {
            const container = document.getElementById('vpnGrid');

            if (vpnList.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <span class="material-icons">vpn_key_off</span>
                        <div class="empty-state-title">${t('no-vpns-configured')}</div>
                        <div class="empty-state-description">${t('add-first-vpn')}</div>
                    </div>
                `;
                return;
            }

            container.innerHTML = vpnList.map(vpn => `
                <div class="vpn-card ${vpn.is_active ? 'active' : ''}">
                    <div class="vpn-card-header">
                        <div>
                            <div class="vpn-name">${vpn.name}</div>
                            <div class="vpn-server">${vpn.server}</div>
                        </div>
                        <div class="status-chip ${vpn.is_active ? 'active' : 'inactive'}">
                            <div class="status-dot"></div>
                            <span>${vpn.is_active ? t('connected') : t('disconnected')}</span>
                        </div>
                    </div>

                    <div class="vpn-details">
                        <div class="vpn-detail">
                            <div class="vpn-detail-label">${t('user')}</div>
                            <div class="vpn-detail-value">${vpn.username}</div>
                        </div>
                        <div class="vpn-detail">
                            <div class="vpn-detail-label">${t('created')}</div>
                            <div class="vpn-detail-value">${new Date(vpn.created_at).toLocaleDateString(currentLanguage === 'pl' ? 'pl-PL' : 'en-US')}</div>
                        </div>
                        <div class="vpn-detail">
                            <div class="vpn-detail-label">${t('last-connection')}</div>
                            <div class="vpn-detail-value">${vpn.last_connected ? new Date(vpn.last_connected).toLocaleDateString(currentLanguage === 'pl' ? 'pl-PL' : 'en-US') : t('never')}</div>
                        </div>
                        <div class="vpn-detail">
                            <div class="vpn-detail-label">${t('status')}</div>
                            <div class="vpn-detail-value">${vpn.is_active ? t('active') : t('inactive')}</div>
                        </div>
                    </div>

                    ${vpn.description ? `<div class="vpn-description">${vpn.description}</div>` : ''}

                    <div class="vpn-actions">
                        ${vpn.is_active ?
                            `<button class="btn btn-danger btn-sm" onclick="disconnectVpn()"><span class="material-icons">power_off</span>${t('disconnect')}</button>` :
                            `<button class="btn btn-success btn-sm" onclick="connectVpn('${vpn.id}')"><span class="material-icons">play_arrow</span>${t('connect')}</button>`
                        }
                        <button class="btn btn-outline btn-sm" onclick="deleteVpn('${vpn.id}')">
                            <span class="material-icons">delete</span>
                            ${t('delete')}
                        </button>
                    </div>
                </div>
            `).join('');
        }

        // Render system status
        function renderSystemStatus() {
            const statusChip = document.getElementById('systemStatusChip');
            const l2tpStatus = document.getElementById('l2tpStatus');
            const activeVpn = document.getElementById('activeVpn');
            const systemLoad = document.getElementById('systemLoad');
            const memoryUsage = document.getElementById('memoryUsage');
            const mainStatus = document.getElementById('mainStatus');

            // System jest zdrowy jeśli L2TP działa LUB jest aktywny VPN
            const isHealthy = systemStatus.main_l2tp || systemStatus.active_vpn || systemStatus.ppp_interface;
            statusChip.className = `status-chip ${isHealthy ? 'active' : 'inactive'}`;
            statusChip.innerHTML = `<div class="status-dot"></div><span>${isHealthy ? t('active') : t('inactive')}</span>`;

            // Główny status
            if (systemStatus.main_l2tp) {
                mainStatus.textContent = t('operational');
            } else if (systemStatus.active_vpn || systemStatus.ppp_interface) {
                mainStatus.textContent = t('bridge-active');
            } else {
                mainStatus.textContent = t('inactive');
            }

            // Pokaż szczegółowy status L2TP
            if (systemStatus.main_l2tp) {
                l2tpStatus.textContent = t('active');
            } else if (systemStatus.active_vpn || systemStatus.ppp_interface) {
                l2tpStatus.textContent = t('bridge');
            } else {
                l2tpStatus.textContent = t('inactive');
            }

            activeVpn.textContent = systemStatus.active_vpn || t('none');
            systemLoad.textContent = systemStatus.system_load || '-';
            memoryUsage.textContent = systemStatus.memory_usage ? `${systemStatus.memory_usage}%` : '-';
        }

        // Connect VPN
        async function connectVpn(vpnId) {
            try {
                showNotification(t('connecting'), 'success');
                const response = await apiCall(`?action=connect&id=${vpnId}`, { method: 'POST' });

                if (response.success) {
                    showNotification(`✓ ${response.message}`, 'success');
                    await loadVpnList();
                    await loadSystemStatus();
                } else {
                    showNotification(`✗ ${response.message}`, 'error');
                }
            } catch (error) {
                showNotification(t('error-connecting'), 'error');
            }
        }

        // Disconnect VPN
        async function disconnectVpn() {
            try {
                const response = await apiCall('?action=disconnect', { method: 'POST' });

                if (response.success) {
                    showNotification(`✓ ${response.message}`, 'success');
                    await loadVpnList();
                    await loadSystemStatus();
                } else {
                    showNotification(`✗ ${response.message}`, 'error');
                }
            } catch (error) {
                showNotification(t('error-disconnecting'), 'error');
            }
        }

        // Delete VPN
        async function deleteVpn(vpnId) {
            if (!confirm(t('confirm-delete'))) return;

            try {
                const response = await apiCall(`?action=vpn&id=${vpnId}`, { method: 'DELETE' });

                if (response.success) {
                    showNotification(t('vpn-deleted'), 'success');
                    await loadVpnList();
                } else {
                    showNotification(t('error-deleting'), 'error');
                }
            } catch (error) {
                showNotification(t('error-deleting'), 'error');
            }
        }

        // Add VPN
        async function addVpn(data) {
            try {
                const response = await apiCall('?action=vpns', {
                    method: 'POST',
                    body: JSON.stringify(data)
                });

                if (response.success) {
                    showNotification(t('vpn-added'), 'success');
                    closeModal('addVpnModal');
                    document.getElementById('addVpnForm').reset();
                    await loadVpnList();
                } else {
                    showNotification(`✗ ${response.error}`, 'error');
                }
            } catch (error) {
                showNotification(t('error-adding'), 'error');
            }
        }

        // Load logs
        async function loadLogs() {
            try {
                const response = await apiCall('?action=logs&lines=50');
                if (response.success) {
                    const logsContent = document.getElementById('logsContent');
                    logsContent.innerHTML = `<pre>${response.data.join('\n') || t('no-logs')}</pre>`;
                }
            } catch (error) {
                document.getElementById('logsContent').innerHTML = `<pre style="color: var(--error);">${t('error-loading-logs')}</pre>`;
            }
        }

        // Modal functions
        function showModal(modalId) {
            document.getElementById(modalId).classList.add('show');
            document.body.style.overflow = 'hidden';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).classList.remove('show');
            document.body.style.overflow = '';
        }

        function showAddVpnModal() {
            showModal('addVpnModal');
        }

        // Refresh functions
        async function refreshVpnList() {
            const icon = document.getElementById('refreshIcon');
            icon.classList.add('refresh-indicator');
            await loadVpnList();
            setTimeout(() => icon.classList.remove('refresh-indicator'), 1000);
        }

        function refreshStatus() {
            const icon = document.getElementById('statusRefreshIcon');
            icon.classList.add('refresh-indicator');
            loadSystemStatus();
            setTimeout(() => icon.classList.remove('refresh-indicator'), 1000);
        }

        function refreshLogs() {
            const icon = document.getElementById('logsRefreshIcon');
            icon.classList.add('refresh-indicator');
            loadLogs();
            setTimeout(() => icon.classList.remove('refresh-indicator'), 1000);
        }

        // Notification system
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;

            const icon = type === 'success' ? 'check_circle' : 'error';
            notification.innerHTML = `
                <span class="material-icons">${icon}</span>
                <span>${message}</span>
            `;

            document.body.appendChild(notification);

            setTimeout(() => notification.classList.add('show'), 100);
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => document.body.removeChild(notification), 300);
            }, 4000);
        }

        // Form handling
        document.getElementById('addVpnForm').addEventListener('submit', (e) => {
            e.preventDefault();

            const data = {
                name: document.getElementById('vpnName').value,
                server: document.getElementById('vpnServer').value,
                username: document.getElementById('vpnUsername').value,
                password: document.getElementById('vpnPassword').value,
                description: document.getElementById('vpnDescription').value
            };

            addVpn(data);
        });

        // Close modals on outside click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('show');
                    document.body.style.overflow = '';
                }
            });
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal.show').forEach(modal => {
                    modal.classList.remove('show');
                    document.body.style.overflow = '';
                });
            }
        });

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            console.log('DOM loaded, initializing...');

            // Load saved language preference first
            const savedLanguage = localStorage.getItem('vpn-manager-language') || 'en';
            currentLanguage = savedLanguage;

            // Update language buttons
            document.querySelectorAll('.language-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            document.getElementById(`lang-${savedLanguage}`).classList.add('active');

            // Update static text elements
            document.querySelectorAll('[data-lang]').forEach(element => {
                const key = element.getAttribute('data-lang');
                if (translations[savedLanguage] && translations[savedLanguage][key]) {
                    element.textContent = translations[savedLanguage][key];
                }
            });

            // Update placeholders
            document.querySelectorAll('[data-placeholder]').forEach(element => {
                const key = element.getAttribute('data-placeholder');
                if (translations[savedLanguage] && translations[savedLanguage][key]) {
                    element.placeholder = translations[savedLanguage][key];
                }
            });

            // Update time immediately and then every second
            updateCurrentTime();
            setInterval(updateCurrentTime, 1000);

            // Load initial data with small delay to ensure DOM is ready
            setTimeout(() => {
                console.log('Loading initial data...');
                loadVpnList();
                loadSystemStatus();
                loadLogs();
            }, 100);

            // Auto-refresh system status every 30 seconds
            setInterval(() => {
                loadSystemStatus();
            }, 30000);

            // Auto-refresh VPN list every 60 seconds
            setInterval(() => {
                loadVpnList();
            }, 60000);

            // Auto-refresh logs every 90 seconds
            setInterval(() => {
                loadLogs();
            }, 90000);
        });
    </script>
</body>
</html>
HTMLEOF

# Set proper permissions
echo -e "${YELLOW}🔧 Setting permissions...${NC}"
chown -R www-data:www-data /var/www/html/vpn-bridge/
chmod 755 /var/www/html/vpn-bridge/
chmod 644 /var/www/html/vpn-bridge/index.html
chmod 644 /var/www/html/vpn-bridge/api.php

# Check service status
echo -e "${YELLOW}🔍 Checking service status...${NC}"
echo ""

echo -e "${BLUE}StrongSwan Status:${NC}"
systemctl status strongswan-starter --no-pager -l || true
echo ""

echo -e "${BLUE}xl2tpd Status:${NC}"
systemctl status xl2tpd --no-pager -l || true
echo ""

echo -e "${BLUE}Apache Status:${NC}"
systemctl status apache2 --no-pager -l || true
echo ""

# Final instructions
echo ""
echo -e "${GREEN}🎉 VPN Bridge Manager Installation Complete!${NC}"
echo ""
echo -e "${YELLOW}Connection Details:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Server IP:      $SERVER_IP"
echo "Username:       $L2TP_USERNAME"
echo "Password:       $(echo "$L2TP_PASSWORD" | sed 's/./*/g')"
echo "Shared Secret:  $SHARED_SECRET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${YELLOW}Access Points:${NC}"
echo "• Web Interface: http://$SERVER_IP/vpn-bridge/"
echo "• API Endpoint:  http://$SERVER_IP/vpn-bridge/api.php"
echo "• Credentials:   /etc/vpn-bridge/credentials.txt"
echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "• Check L2TP logs:    sudo journalctl -u xl2tpd -f"
echo "• Check IPSec status: sudo ipsec statusall"
echo "• Check interfaces:   ip addr show"
echo "• Check firewall:     iptables -L -n"
echo "• View credentials:   sudo cat /etc/vpn-bridge/credentials.txt"
echo ""
echo -e "${GREEN}Installation completed successfully! 🚀${NC}"
echo ""
echo -e "${BLUE}Note: Credentials have been saved to /etc/vpn-bridge/credentials.txt${NC}"