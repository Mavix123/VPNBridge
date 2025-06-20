<?php
$command = "systemctl is-active xl2tpd.service";
$output = [];
$returnCode = 0;
exec('sudo ' . $command . ' 2>&1', $output, $returnCode);

echo "Command: sudo $command\n";
echo "Return Code: $returnCode\n";
echo "Output: " . implode("\n", $output) . "\n";
echo "Trimmed Output: '" . trim(implode("\n", $output)) . "'\n";
echo "Is Active: " . (trim(implode("\n", $output)) === 'active' ? 'true' : 'false') . "\n";
echo "String length: " . strlen(trim(implode("\n", $output))) . "\n";
echo "Hex dump: " . bin2hex(trim(implode("\n", $output))) . "\n";
