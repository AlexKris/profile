<?php
namespace App\Support {
    class AbstractProtocol
    {
        public $servers = [];
        public $user = ['u' => 0, 'd' => 0, 'transfer_enable' => 1024, 'expired_at' => 0];
    }
}

namespace Illuminate\Support\Facades {
    class File
    {
        public static function exists($path): bool { return is_file($path); }
        public static function get($path): string { return file_get_contents($path); }
    }

    class Log
    {
        public static array $warnings = [];

        public static function warning($message): void
        {
            self::$warnings[] = $message;
        }
    }
}

namespace {
    function base_path($path) { return $GLOBALS['argv'][1] . '/' . $path; }
    function admin_setting($key, $default = null) { return $default; }
    function subscribe_template($type) { return file_get_contents(base_path('admin-template.json')); }

    function request()
    {
        return new class {
            public function query($key, $default = null) { return $GLOBALS['argv'][3] ?? $default; }
        };
    }

    function response()
    {
        return new class {
            public array $config = [];
            public function json(array $config): self { $this->config = $config; return $this; }
            public function header($name, $value): self { return $this; }
        };
    }

    function data_get($value, $path, $default = null)
    {
        foreach (explode('.', $path) as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return $default;
            }
            $value = $value[$key];
        }
        return $value;
    }

    require dirname(__DIR__) . '/protocols_data/SingBox.php';

    try {
        $names = json_decode($argv[2], true, 512, JSON_THROW_ON_ERROR);
        $protocol = new \App\Protocols\SingBox();
        foreach ($names as $name) {
            $protocol->servers[] = [
                'name' => $name,
                'type' => 'shadowsocks',
                'host' => '192.0.2.1',
                'port' => 443,
                'password' => 'test-only-placeholder',
                'protocol_settings' => ['cipher' => 'aes-128-gcm'],
            ];
        }
        $response = $protocol->handle();
        echo json_encode([
            'config' => $response->config,
            'warnings' => \Illuminate\Support\Facades\Log::$warnings,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    } catch (\Throwable $error) {
        echo json_encode(['error' => $error->getMessage()], JSON_THROW_ON_ERROR);
        exit(1);
    }
}
