<?php
namespace App\Protocols;

use App\Utils\Helper;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use App\Support\AbstractProtocol;

class SingBox extends AbstractProtocol
{
    public $flags = ['sing-box', 'hiddify', 'sfm'];
    private $config;
    const CUSTOM_TEMPLATE_FILE = 'resources/rules/custom.sing-box.json';
    const FAKEIP_TEMPLATE_FILE = 'resources/rules/custom.sing-box.fakeip.json';
    const REALIP_TEMPLATE_FILE = 'resources/rules/custom.sing-box.realip.json';
    const DEFAULT_TEMPLATE_FILE = 'resources/rules/default.sing-box.json';

    /**
     * 多客户端协议支持配置
     */
    protected $protocolRequirements = [
        'sing-box' => [
            'vless' => [
                'base_version' => '1.5.0',
                'protocol_settings.flow' => [
                    'xtls-rprx-vision' => '1.5.0'
                ],
                'protocol_settings.tls' => [
                    '2' => '1.6.0' // Reality
                ]
            ],
            'hysteria' => [
                'base_version' => '1.5.0',
                'protocol_settings.version' => [
                    '2' => '1.5.0' // Hysteria 2
                ]
            ],
            'tuic' => [
                'base_version' => '1.5.0'
            ],
            'ssh' => [
                'base_version' => '1.8.0'
            ],
            'juicity' => [
                'base_version' => '1.7.0'
            ],
            'shadowtls' => [
                'base_version' => '1.6.0'
            ],
            'wireguard' => [
                'base_version' => '1.5.0'
            ],
            'anytls' => [
                'base_version' => '1.12.0'
            ]
        ]
    ];

    public function handle()
    {
        $appName = admin_setting('app_name', 'XBoard');
        $this->config = $this->loadConfig();
        $this->buildOutbounds();
        $this->buildRule();
        $this->adaptConfigForVersion();
        $user = $this->user;

        return response()
            ->json($this->config)
            ->header('profile-title', 'base64:' . base64_encode($appName))
            ->header('subscription-userinfo', "upload={$user['u']}; download={$user['d']}; total={$user['transfer_enable']}; expire={$user['expired_at']}")
            ->header('profile-update-interval', '24');
    }

    protected function loadConfig()
    {
        $profile = strtolower(trim((string) request()->query('profile', 'fakeip')));
        if (!in_array($profile, ['fakeip', 'realip'], true)) {
            $profile = 'fakeip';
        }

        $templateFile = $profile === 'realip' ? self::REALIP_TEMPLATE_FILE : self::FAKEIP_TEMPLATE_FILE;
        $templatePath = base_path($templateFile);

        if (File::exists($templatePath)) {
            $jsonData = File::get($templatePath);
        } else {
            Log::warning("[SingBox] template file not found: {$templateFile}; fallback to admin singbox template");
            $jsonData = subscribe_template('singbox');
        }

        return is_array($jsonData) ? $jsonData : json_decode($jsonData, true);
    }

    protected function buildOutbounds()
    {
        $outbounds = $this->config['outbounds'];
        $proxies = [];
        foreach ($this->servers as $item) {
            $protocol_settings = $item['protocol_settings'];
            if ($item['type'] === 'shadowsocks') {
                $proxies[] = $this->buildShadowsocks($item['password'], $item);
            }
            if ($item['type'] === 'trojan') {
                $proxies[] = $this->buildTrojan($this->user['uuid'], $item);
            }
            if ($item['type'] === 'vmess') {
                $proxies[] = $this->buildVmess($this->user['uuid'], $item);
            }
            if (
                $item['type'] === 'vless'
                && in_array(data_get($protocol_settings, 'network'), ['tcp', 'ws', 'grpc', 'http', 'quic', 'httpupgrade'])
            ) {
                $proxies[] = $this->buildVless($this->user['uuid'], $item);
            }
            if ($item['type'] === 'hysteria') {
                $proxies[] = $this->buildHysteria($this->user['uuid'], $item);
            }
            if ($item['type'] === 'tuic') {
                $proxies[] = $this->buildTuic($this->user['uuid'], $item);
            }
            if ($item['type'] === 'anytls') {
                $proxies[] = $this->buildAnyTLS($this->user['uuid'], $item);
            }
            if ($item['type'] === 'socks') {
                $proxies[] = $this->buildSocks($this->user['uuid'], $item);
            }
            if ($item['type'] === 'http') {
                $proxies[] = $this->buildHttp($this->user['uuid'], $item);
            }
        }

        $allTags = array_column($proxies, 'tag');
        $keywordMatchedTags = [];
        $othersOutboundIndexes = [];

        foreach ($outbounds as $index => &$outbound) {
            if (!in_array($outbound['type'], ['urltest', 'selector'])) {
                continue;
            }

            $include = $outbound['include'] ?? null;
            $exclude = $outbound['exclude'] ?? null;
            $fallback = $outbound['fallback'] ?? null;
            $filter = $outbound['_filter'] ?? null;
            $filterAnd = $outbound['_filter_and'] ?? null;
            $filterExclude = $outbound['_filter_exclude'] ?? null;

            unset(
                $outbound['include'],
                $outbound['exclude'],
                $outbound['fallback'],
                $outbound['_filter'],
                $outbound['_filter_and'],
                $outbound['_filter_exclude']
            );

            if ($include !== null || $exclude !== null || $fallback !== null) {
                $tags = $allTags;

                if ($include !== null && $include !== '') {
                    $tags = array_values(array_filter(
                        $tags,
                        fn($tag) => $this->matchesPattern($include, $tag)
                    ));
                }

                if ($exclude !== null && $exclude !== '') {
                    $tags = array_values(array_filter(
                        $tags,
                        fn($tag) => !$this->matchesPattern($exclude, $tag)
                    ));
                }

                if (empty($tags) && $fallback !== null) {
                    $tags = $this->resolveFallback($fallback, $allTags, $outbounds, $outbound['tag'] ?? '');
                }

                if (!empty($tags)) {
                    array_push($outbound['outbounds'], ...$tags);
                } elseif (empty($outbound['outbounds'])) {
                    $outbound['outbounds'][] = 'Direct';
                }

                continue;
            }

            if ($filter === 'others') {
                $othersOutboundIndexes[] = $index;
            } elseif (is_array($filter)) {
                $matched = [];
                foreach ($proxies as $proxy) {
                    $tag = $proxy['tag'];

                    // Must match at least one keyword in _filter (OR)
                    $orMatch = false;
                    foreach ($filter as $keyword) {
                        if (mb_stripos($tag, $keyword) !== false) {
                            $orMatch = true;
                            break;
                        }
                    }
                    if (!$orMatch) {
                        continue;
                    }

                    // If _filter_and is set, must ALSO match at least one of its keywords (AND of two OR groups)
                    if (is_array($filterAnd) && !empty($filterAnd)) {
                        $andMatch = false;
                        foreach ($filterAnd as $keyword) {
                            if (mb_stripos($tag, $keyword) !== false) {
                                $andMatch = true;
                                break;
                            }
                        }
                        if (!$andMatch) {
                            continue;
                        }
                    }

                    // If _filter_exclude is set, must NOT match any of its keywords
                    if (is_array($filterExclude) && !empty($filterExclude)) {
                        $excluded = false;
                        foreach ($filterExclude as $keyword) {
                            if (mb_stripos($tag, $keyword) !== false) {
                                $excluded = true;
                                break;
                            }
                        }
                        if ($excluded) {
                            continue;
                        }
                    }

                    $matched[] = $tag;
                    $keywordMatchedTags[] = $tag;
                }
                array_push($outbound['outbounds'], ...$matched);
            } elseif ($filter !== 'none' && $filter !== 'others') {
                // "all" or no _filter: inject all nodes
                array_push($outbound['outbounds'], ...$allTags);
            }
        }
        unset($outbound);

        // Pass 2: "others" — nodes not matched by any keyword filter
        $othersNodes = array_values(array_diff($allTags, array_unique($keywordMatchedTags)));
        foreach ($othersOutboundIndexes as $index) {
            array_push($outbounds[$index]['outbounds'], ...$othersNodes);
        }

        // Pass 3: cleanup — fallback empty outbounds, remove _filter
        foreach ($outbounds as &$outbound) {
            if (!in_array($outbound['type'], ['urltest', 'selector'])) {
                continue;
            }
            if (empty($outbound['outbounds'])) {
                $outbound['outbounds'][] = 'Direct';
            }
        }
        unset($outbound);

        $outbounds = array_merge($outbounds, $proxies);
        $this->config['outbounds'] = $outbounds;
        return $outbounds;
    }

    /**
     * Safely match a template pattern against a node tag.
     */
    protected function matchesPattern(string $pattern, string $subject): bool
    {
        static $cache = [];

        if (!isset($cache[$pattern])) {
            $trimmed = trim($pattern);
            $first = $trimmed !== '' ? $trimmed[0] : '';
            $looksDelimited = in_array($first, ['/', '#', '~', '@', '%'], true)
                && preg_match('/^(.)(.*)\1[a-zA-Z]*$/us', $trimmed) === 1;

            $cache[$pattern] = $looksDelimited
                ? $trimmed
                : '~' . str_replace('~', '\~', $pattern) . '~ui';
        }

        $result = @preg_match($cache[$pattern], $subject);

        if ($result === false) {
            $err = preg_last_error_msg();
            Log::warning("[SingBox] invalid outbound pattern {$pattern}: {$err}");
            $cache[$pattern] = '~(*FAIL)~';
            return false;
        }

        return $result === 1;
    }

    protected function resolveFallback($fallback, array $allTags, array $outbounds, string $groupTag): array
    {
        $candidates = is_array($fallback) ? $fallback : [$fallback];
        $templateTags = array_column($outbounds, 'tag');

        foreach ($candidates as $candidate) {
            if (!is_string($candidate) || $candidate === '') {
                continue;
            }

            if (in_array($candidate, $allTags, true) || in_array($candidate, $templateTags, true)) {
                return [$candidate];
            }

            $matched = array_values(array_filter(
                $allTags,
                fn($tag) => $this->matchesPattern($candidate, $tag)
            ));

            if (!empty($matched)) {
                return $matched;
            }
        }

        Log::warning("[SingBox] outbound group '{$groupTag}' fallback unresolved; group left empty");
        return [];
    }

    /**
     * Build rule
     */
    protected function buildRule()
    {
        $rules = $this->config['route']['rules'];
        // Force the nodes ip to be a direct rule
        // array_unshift($rules, [
        //     'ip_cidr' => collect($this->servers)->pluck('host')->map(function ($host) {
        //         return filter_var($host, FILTER_VALIDATE_IP) ? [$host] : Helper::getIpByDomainName($host);
        //     })->flatten()->unique()->values(),
        //     'outbound' => 'direct',
        // ]);
        $this->config['route']['rules'] = $rules;
    }

    /**
     * 根据客户端版本自适应配置格式。
     */
    protected function adaptConfigForVersion(): void
    {
        $coreVersion = $this->getSingBoxCoreVersion();
        if (empty($coreVersion)) {
            return;
        }

        if (version_compare($coreVersion, '1.14.0', '>=')) {
            $this->migrateDnsFor114();
            $this->migrateCacheFileFor114();
            $this->migrateRuleSetDownloadsFor114();
        }
    }

    private function getSingBoxCoreVersion(): ?string
    {
        if (!empty($this->userAgent)) {
            if (preg_match('/sing-box[\/\s]+v?(\d+(?:\.\d+){0,2})/i', $this->userAgent, $matches)) {
                return $matches[1];
            }
        }

        if (empty($this->clientVersion)) {
            return null;
        }

        if ($this->clientName === 'sing-box') {
            return $this->clientVersion;
        }

        return '1.13.0';
    }

    private function migrateDnsFor114(): void
    {
        if (!isset($this->config['dns'])) {
            return;
        }

        $removedStrategy = false;
        if (isset($this->config['dns']['rules']) && is_array($this->config['dns']['rules'])) {
            foreach ($this->config['dns']['rules'] as &$rule) {
                if (isset($rule['strategy'])) {
                    unset($rule['strategy']);
                    $removedStrategy = true;
                }
            }
            unset($rule);
        }

        if ($removedStrategy && empty($this->config['dns']['strategy'])) {
            $this->config['dns']['strategy'] = 'prefer_ipv4';
        }

        unset($this->config['dns']['independent_cache']);
    }

    private function migrateCacheFileFor114(): void
    {
        if (!isset($this->config['experimental']['cache_file'])) {
            return;
        }

        $cacheFile = &$this->config['experimental']['cache_file'];
        if (!empty($cacheFile['store_rdrc'])) {
            $cacheFile['store_dns'] = true;
        }
        unset($cacheFile['store_rdrc'], $cacheFile['rdrc_timeout']);
    }

    private function migrateRuleSetDownloadsFor114(): void
    {
        if (empty($this->config['route']['rule_set']) || !is_array($this->config['route']['rule_set'])) {
            return;
        }

        foreach ($this->config['route']['rule_set'] as &$ruleSet) {
            if (($ruleSet['type'] ?? null) !== 'remote' || empty($ruleSet['download_detour'])) {
                continue;
            }

            $ruleSet['http_client'] = [
                'detour' => $ruleSet['download_detour'],
            ];
            unset($ruleSet['download_detour']);
        }
        unset($ruleSet);
    }

    protected function buildShadowsocks($password, $server)
    {
        $protocol_settings = data_get($server, 'protocol_settings');
        $array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'shadowsocks';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['method'] = data_get($protocol_settings, 'cipher');
        $array['password'] = data_get($server, 'password', $password);
        if (data_get($protocol_settings, 'plugin') && data_get($protocol_settings, 'plugin_opts')) {
            $array['plugin'] = data_get($protocol_settings, 'plugin');
            $array['plugin_opts'] = data_get($protocol_settings, 'plugin_opts', '');
        }

        return $array;
    }


    protected function buildVmess($uuid, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $array = [
            'tag' => $server['name'],
            'type' => 'vmess',
            'server' => $server['host'],
            'server_port' => $server['port'],
            'uuid' => $uuid,
            'security' => 'auto',
            'alter_id' => 0,
            'transport' => [],
            'tls' => $protocol_settings['tls'] ? [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls_settings.allow_insecure'),
            ] : null
        ];
        if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
            $array['tls']['server_name'] = $serverName;
        }

        $transport = match ($protocol_settings['network']) {
            'tcp' => [
                'type' => 'http',
                'path' => Arr::random(data_get($protocol_settings, 'network_settings.header.request.path', ['/']))
            ],
            'ws' => [
                'type' => 'ws',
                'path' => data_get($protocol_settings, 'network_settings.path'),
                'headers' => ($host = data_get($protocol_settings, 'network_settings.headers.Host')) ? ['Host' => $host] : null,
                'max_early_data' => 2048,
                'early_data_header_name' => 'Sec-WebSocket-Protocol'
            ],
            'grpc' => [
                'type' => 'grpc',
                'service_name' => data_get($protocol_settings, 'network_settings.serviceName')
            ],
            default => null
        };

        if ($transport) {
            $array['transport'] = array_filter($transport, fn($value) => !is_null($value));
        }
        return $array;
    }

    protected function buildVless($password, $server)
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            "type" => "vless",
            "tag" => $server['name'],
            "server" => $server['host'],
            "server_port" => $server['port'],
            "uuid" => $password,
            "packet_encoding" => "xudp",
            'flow' => data_get($protocol_settings, 'flow', ''),
        ];

        if ($protocol_settings['tls']) {
            $tlsConfig = [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls_settings.allow_insecure'),
                'utls' => [
                    'enabled' => true,
                    'fingerprint' => Helper::getRandFingerprint()
                ]
            ];

            switch ($protocol_settings['tls']) {
                case 1:
                    if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
                        $tlsConfig['server_name'] = $serverName;
                    }
                    break;
                case 2:
                    $tlsConfig['server_name'] = data_get($protocol_settings, 'reality_settings.server_name');
                    $tlsConfig['reality'] = [
                        'enabled' => true,
                        'public_key' => data_get($protocol_settings, 'reality_settings.public_key'),
                        'short_id' => data_get($protocol_settings, 'reality_settings.short_id')
                    ];
                    break;
            }

            $array['tls'] = $tlsConfig;
        }

        $transport = match ($protocol_settings['network']) {
            'tcp' => data_get($protocol_settings, 'network_settings.header.type') == 'http' ? [
                'type' => 'http',
                'path' => Arr::random(data_get($protocol_settings, 'network_settings.header.request.path', ['/']))
            ] : null,
            'ws' => array_filter([
                'type' => 'ws',
                'path' => data_get($protocol_settings, 'network_settings.path'),
                'headers' => ($host = data_get($protocol_settings, 'network_settings.headers.Host')) ? ['Host' => $host] : null,
                'max_early_data' => 2048,
                'early_data_header_name' => 'Sec-WebSocket-Protocol'
            ], fn($value) => !is_null($value)),
            'grpc' => [
                'type' => 'grpc',
                'service_name' => data_get($protocol_settings, 'network_settings.serviceName')
            ],
            'h2' => [
                'type' => 'http',
                'host' => data_get($protocol_settings, 'network_settings.host'),
                'path' => data_get($protocol_settings, 'network_settings.path')
            ],
            'httpupgrade' => [
                'type' => 'httpupgrade',
                'path' => data_get($protocol_settings, 'network_settings.path'),
                'host' => data_get($protocol_settings, 'network_settings.host', $server['host']),
                'headers' => data_get($protocol_settings, 'network_settings.headers')
            ],
            default => null
        };

        if ($transport) {
            $array['transport'] = array_filter($transport, fn($value) => !is_null($value));
        }

        return $array;
    }

    protected function buildTrojan($password, $server)
    {
        $protocol_settings = $server['protocol_settings'];
        $array = [
            'tag' => $server['name'],
            'type' => 'trojan',
            'server' => $server['host'],
            'server_port' => $server['port'],
            'password' => $password,
            'tls' => [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'allow_insecure', false),
            ]
        ];
        if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
            $array['tls']['server_name'] = $serverName;
        }
        $transport = match (data_get($protocol_settings, 'network')) {
            'grpc' => [
                'type' => 'grpc',
                'service_name' => data_get($protocol_settings, 'network_settings.serviceName')
            ],
            'ws' => [
                'type' => 'ws',
                'path' => data_get($protocol_settings, 'network_settings.path'),
                'headers' => data_get($protocol_settings, 'network_settings.headers.Host') ? ['Host' => [data_get($protocol_settings, 'network_settings.headers.Host')]] : null,
                'max_early_data' => 2048,
                'early_data_header_name' => 'Sec-WebSocket-Protocol'
            ],
            default => null
        };
        $array['transport'] = $transport;
        return $array;
    }

    protected function buildHysteria($password, $server): array
    {
        $protocol_settings = $server['protocol_settings'];
        $baseConfig = [
            'server' => $server['host'],
            'server_port' => $server['port'],
            'tag' => $server['name'],
            'tls' => [
                'enabled' => true,
                'insecure' => (bool) $protocol_settings['tls']['allow_insecure'],
            ]
        ];
        // 支持 1.11.0 版本及以上 `server_ports` 和 `hop_interval` 配置
        if ($this->supportsFeature('sing-box', '1.11.0')) {
            if (isset($server['ports'])) {
                $baseConfig['server_ports'] = [str_replace('-', ':', $server['ports'])];
            }
            if (isset($protocol_settings['hop_interval'])) {
                $baseConfig['hop_interval'] = "{$protocol_settings['hop_interval']}s";
            }
        }

        if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
            $baseConfig['tls']['server_name'] = $serverName;
        }
        $speedConfig = [
            'up_mbps' => $protocol_settings['bandwidth']['up'],
            'down_mbps' => $protocol_settings['bandwidth']['down'],
        ];
        $versionConfig = match (data_get($protocol_settings, 'version', 1)) {
            2 => [
                'type' => 'hysteria2',
                'password' => $password,
                'obfs' => $protocol_settings['obfs']['open'] ? [
                    'type' => $protocol_settings['obfs']['type'],
                    'password' => $protocol_settings['obfs']['password']
                ] : null,
            ],
            default => [
                'type' => 'hysteria',
                'auth_str' => $password,
                'obfs' => $protocol_settings['obfs']['password'],
                'disable_mtu_discovery' => true,
            ]
        };

        return array_merge(
            $baseConfig,
            $speedConfig,
            $versionConfig
        );
    }

    protected function buildTuic($password, $server): array
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            'type' => 'tuic',
            'tag' => $server['name'],
            'server' => $server['host'],
            'server_port' => $server['port'],
            'congestion_control' => data_get($protocol_settings, 'congestion_control', 'cubic'),
            'udp_relay_mode' => data_get($protocol_settings, 'udp_relay_mode', 'native'),
            'zero_rtt_handshake' => true,
            'heartbeat' => '10s',
            'tls' => [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls.allow_insecure', false),
                'alpn' => data_get($protocol_settings, 'alpn', ['h3']),
            ]
        ];

        if ($serverName = data_get($protocol_settings, 'tls.server_name')) {
            $array['tls']['server_name'] = $serverName;
        }

        if (data_get($protocol_settings, 'version') === 4) {
            $array['token'] = $password;
        } else {
            $array['uuid'] = $password;
            $array['password'] = $password;
        }

        return $array;
    }

    protected function buildAnyTLS($password, $server): array
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            'type' => 'anytls',
            'tag' => $server['name'],
            'server' => $server['host'],
            'password' => $password,
            'server_port' => $server['port'],
            'tls' => [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls.allow_insecure', false),
            ]
        ];

        // anytls 走 TCP+TLS，不是 HTTP/3。只在用户显式配置 alpn 时才写入，
        // 避免强制下发 ['h3'] 导致 sing-box 客户端 TLS 握手失败（Surge 忽略 ALPN 才能通）。
        $alpn = data_get($protocol_settings, 'alpn');
        if (!empty($alpn)) {
            $array['tls']['alpn'] = $alpn;
        }

        if ($serverName = data_get($protocol_settings, 'tls.server_name')) {
            $array['tls']['server_name'] = $serverName;
        }

        return $array;
    }

    protected function buildSocks($password, $server): array
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            'type' => 'socks',
            'tag' => $server['name'],
            'server' => $server['host'],
            'server_port' => $server['port'],
            'version' => '5', // 默认使用 socks5
            'username' => $password,
            'password' => $password,
        ];

        if (data_get($protocol_settings, 'udp_over_tcp')) {
            $array['udp_over_tcp'] = true;
        }

        return $array;
    }

    protected function buildHttp($password, $server): array
    {
        $protocol_settings = data_get($server, 'protocol_settings', []);
        $array = [
            'type' => 'http',
            'tag' => $server['name'],
            'server' => $server['host'],
            'server_port' => $server['port'],
            'username' => $password,
            'password' => $password,
        ];

        if ($path = data_get($protocol_settings, 'path')) {
            $array['path'] = $path;
        }

        if ($headers = data_get($protocol_settings, 'headers')) {
            $array['headers'] = $headers;
        }

        if (data_get($protocol_settings, 'tls')) {
            $array['tls'] = [
                'enabled' => true,
                'insecure' => (bool) data_get($protocol_settings, 'tls_settings.allow_insecure', false),
            ];

            if ($serverName = data_get($protocol_settings, 'tls_settings.server_name')) {
                $array['tls']['server_name'] = $serverName;
            }
        }

        return $array;
    }
}
