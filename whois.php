<!DOCTYPE html>
<html lang="zh-Hant">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow"> <!-- Prevent indexing this page -->
    <title>WHOIS 查詢結果</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            padding: 20px;
            margin: 0;
            position: relative;
            min-height: 100vh;
        }
        .container {
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            max-width: 800px;
            margin: 20px auto;
        }
        h2 {
            color: #333;
            margin-bottom: 10px;
        }
        pre {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #ccc;
            white-space: pre-wrap;
            font-size: 14px;
            line-height: 1.5;
        }
        .error {
            color: red;
        }
        .copyright {
            position: fixed;
            bottom: 10px;
            right: 10px;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php
        if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['query_domain']) && isset($_GET['type'])) {
            $domain = filter_var($_GET['query_domain'], FILTER_SANITIZE_STRING);
            $type = filter_var($_GET['type'], FILTER_SANITIZE_STRING);

            if (empty($domain)) {
                echo "<h2>錯誤</h2>";
                echo "<p class='error'>無效的域名。</p>";
                exit;
            }
            
            if ($type === 'globe') {
                // Open socket connection to IANA WHOIS server
                $socket = fsockopen('whois.iana.org', 43);
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

                    // Replace IANA WHOIS information with BIV.COM.TW information
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
                    echo "<h2>WHOIS 查詢結果: $domain</h2>";
                    echo "<pre>" . htmlspecialchars($response) . "</pre>";
                } else {
                    echo "<h2>查詢失敗</h2>";
                    echo "<p class='error'>無法連接 WHOIS 服務器。</p>";
                }
            } elseif ($type === 'tw' && substr($domain, -3) === '.tw') {
                // Open socket connection to TWNIC WHOIS server
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

                    // Replace TWNIC WHOIS information with BIV.COM.TW information
                    $response = str_replace(
                        [
                            '% TWNIC WHOIS server',
                            'for more information on TWNIC, visit http://www.twnic.net.tw',
                        ],
                        [
                            '% BIV.COM.TW WHOIS server',
                            'for more information on BIV.COM.TW, visit http://whois.biv.com.tw',
                        ],
                        $response
                    );

                    // Display WHOIS information
                    echo "<h2>WHOIS 查詢結果: $domain</h2>";
                    echo "<pre>" . htmlspecialchars($response) . "</pre>";
                } else {
                    echo "<h2>查詢失敗</h2>";
                    echo "<p class='error'>無法連接 WHOIS 服務器。</p>";
                }
            } else {
                echo "<h2>錯誤</h2>";
                echo "<p class='error'>僅能查詢台灣網域 (.tw) 或其他指定的網域</p>";
            }
        } else {
            echo "<h2>錯誤</h2>";
            echo "<p class='error'>無效的 WHOIS 查詢</p>";
        }
        ?>
    </div>

    <div class="copyright">
        &copy; 2024 whois.biv.com.tw corp. All rights reserved.
    </div>
</body>
</html>
