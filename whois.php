<?php
header('Content-Type: application/json');

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['query_domain'])) {
    $domain = filter_input(INPUT_POST, 'query_domain', FILTER_SANITIZE_STRING);

    // Validate if the domain is a Taiwanese domain (.tw)
    if (preg_match('/\.tw$/i', $domain)) {
        // Open socket connection to WHOIS server
        $socket = fsockopen('whois.twnic.net.tw', 43);
        if ($socket) {
            // Send domain query
            fputs($socket, $domain . "\r\n");

            // Buffer to store WHOIS response
            $response = '';
            while (!feof($socket)) {
                $response .= fgets($socket, 128);
            }

            // Close socket connection
            fclose($socket);

            // Check if the response indicates the domain cannot be queried
            if (stripos($response, 'No match for') !== false) {
                echo json_encode(['error' => '該名稱無法查詢']);
            } else {
                // Replace WHOIS server information
                $response = str_replace(
                    [
                        '% IANA WHOIS server',
                        'for more information on IANA, visit http://www.iana.org',
                    ],
                    [
                        '% BIV.COM.TW WHOIS server',
                        'for more information on BIV.COM.TW, visit http://whois.biv.com.tw',
                    ],
                    $response
                );

                // Display WHOIS information
                echo json_encode(['whois_info' => htmlspecialchars($response)]);
            }
        } else {
            echo json_encode(['error' => '無法連接 WHOIS 服務器。']);
        }
    } else {
        echo json_encode(['error' => '僅能查詢台灣網域 (.tw)']);
    }
} else {
    echo json_encode(['error' => '無效的 WHOIS 查詢']);
}
?>
