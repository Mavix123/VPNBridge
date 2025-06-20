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
