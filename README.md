# XMBox
Sing-box server for NuxtJs version of XMPlus management panel

#### Config directory
```
cd /etc/XMBox
```

### Onclick XMBox backennd Install
```
bash <(curl -Ls https://raw.githubusercontent.com/XMPlusDev/XMBox/script/install.sh)
```

### /etc/XMBox/config.yaml
```
ApiConfig:                                        # API Configuraion
  ApiHost: "https://api.xyz.com"                  # Panel api host address
  ApiKey: "123"                                   # Server api key from admin general settigs 
  ServerID: 1                                     # Important: The id of the server and not node id.
  Timeout: 30                                     # Connection time out. Cannot be higer than api update interval.
CertConfig:                                       # Cert config for when cert mode is dns
  Provider: cloudflare                            
  Providers:
    cloudflare:                                   # Provider name. eg, cloudflare. Set in panel tlsSettings - dnsProvider https://go-acme.github.io/lego/dns/index.html
      CertEnv:
        CLOUDFLARE_DNS_API_TOKEN: x               # Cert Provider environment variables.
RedisConfig:
  Enable: false                                   # Enable the global ip limit
  Network: tcp                                    # Redis protocol, tcp or unix
  Addr: 127.0.0.1:6379                            # Redis server address, or unix socket path
  Username:                                       # Redis username
  Password:                                       # Redis password
  DB: 0                                           # Redis DB
  Timeout: 10                                     # Timeout for redis request
ReverbConfig:
  - Enable: false                                 # Enable websocket to trigger real-time subscription and node updates from panel
    Host: "api.xyz.com:443"                       # Reverb REVERB_HOST:REVERB_PORT  in .env for api /home/XMPlusPanel/.env 
    AppKey:                                       # REVERB_APP_KEY in .env for api /home/XMPlusPanel/.env
    AppSecret:                                    # REVERB_APP_SECRET in .env for api /home/XMPlusPanel/.env
    UseTLS: true                                  # Set to true if tls enabled for api
InstanceConfig:                                  
  NtpConfig:
    Enable: false
    Server: time.cloudflare.com
    ServerPort: 123
  MultiplexConfig:                                
    Enabled: true                                 # true, flase
    Padding: true                                 # true, flase
  LogConfig:
    Level: info                                   # debug | info | warn | error
    Disabled: true                                # true, flase
    Output: #/etc/XMBox/output.log
  DnsConfig:
    Enable: true                                  # Use custom dns config, ensure that you set the dns.json correctly
    Path: /etc/XMBox/dns.json                     # /etc/XMRay/dns.json      https://xtls.github.io/config/dns.html
  RouteConfig:
    Enable: false                                 # Use custom route config, ensure that you set the route.json correctly
    Path: /etc/XMBox/route.json 
```

## XMPlus Panel Server configuration

### Network Settings

### Fallback Settings (`fallback`) 

> **Applies to:** `trojan` node type only.

Fallback redirect unrecognised or non-matching connections to another local service (e.g. a web server or another proxy). Configured in the panel's **Network Settings** JSON.

```json
{
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 80
  }
}
```

<details>
<summary><strong>Example of network settings with fallback settings</strong></summary>
```
  "listen_ip": "0.0.0.0",
  "listen_port": "443",
  "tcp_fast_open": true,
  "transportProtocol": {
    "type": "tcp",
    "settings": {
      "header": {
        "type": "none"
      }
    }
  },
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 80
  },
  //vless
  "flow": "xtls-rprx-vision",
  // shadowsocks
  "cipher": "aes-128-gcm",
  // hysteria
  //obfs_type(salamander or gecko)
  "obfs_type": "salamander",
  "obfs_password": "password",
  "geckoMinPacketSize": 512,
  "geckoMaxPacketSize": 1200,
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  "realm_server_url": "",
  "realm_token": "",
  "realm_id": "",
  "realm_stun_servers": [],
  //tuic
  "congestion_control": "bbr",
  //naive
  "enable_quic" : false,
  "quic_congestion_control": "bbr",
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "www.microsoft.com",
  "handshake_server_port": 443
```

</details>

#### TCP
```
{
  "listen_ip": "0.0.0.0",
  "listen_port": "443",
  "tcp_fast_open": true,
  "transportProtocol": {
    "type": "tcp",
    "settings": {
      "header": {
        "type": "none"
      }
    }
  },
  //vless
  "flow": "xtls-rprx-vision",
  // shadowsocks
  "cipher": "aes-128-gcm",
  // hysteria
  //obfs_type(salamander or gecko)
  "obfs_type": "salamander",
  "obfs_password": "password",
  "geckoMinPacketSize": 512,
  "geckoMaxPacketSize": 1200,
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  "realm_server_url": "",
  "realm_token": "",
  "realm_id": "",
  "realm_stun_servers": [],
  //tuic
  "congestion_control": "bbr",
  //naive
  "enable_quic" : false,
  "quic_congestion_control": "bbr",
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "www.microsoft.com",
  "handshake_server_port": 443
}
```
#### TCP + HTTP
```
{
  "listen_ip": "0.0.0.0",
  "listen_port": "443",
  "tcp_fast_open": true,
  "transportProtocol": {
    "type": "tcp",
    "settings": {
      "header": {
        "type": "http",
        "path": "/",
        "host": "www.cloudflare.com",
		"method": "GET"
      }
    }
  },
  //vless
  "flow": "xtls-rprx-vision",
  // shadowsocks
  "cipher": "aes-128-gcm",
  // hysteria
  //obfs_type(salamander or gecko)
  "obfs_type": "salamander",
  "obfs_password": "password",
  "geckoMinPacketSize": 512,
  "geckoMaxPacketSize": 1200,
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  "realm_server_url": "",
  "realm_token": "",
  "realm_id": "",
  "realm_stun_servers": [],
  //tuic
  "congestion_control": "bbr",
  //naive
  "enable_quic" : false,
  "quic_congestion_control": "bbr",
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "www.microsoft.com",
  "handshake_server_port": 443
}
```
####  WS
```
{
  "listen_ip": "0.0.0.0",
  "listen_port": "443",
  "tcp_fast_open": true,
  "transportProtocol": {
    "type": "ws",
    "settings": {
      "path": "/",
      "max_early_data": 0
    }
  },
  //vless
  "flow": "xtls-rprx-vision",
  // shadowsocks
  "cipher": "aes-128-gcm",
  // hysteria
  //obfs_type(salamander or gecko)
  "obfs_type": "salamander",
  "obfs_password": "password",
  "geckoMinPacketSize": 512,
  "geckoMaxPacketSize": 1200,
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  "realm_server_url": "",
  "realm_token": "",
  "realm_id": "",
  "realm_stun_servers": [],
  //tuic
  "congestion_control": "bbr",
  //naive
  "enable_quic" : false,
  "quic_congestion_control": "bbr",
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "www.microsoft.com",
  "handshake_server_port": 443
}
```

####  GRPC
```
{
  "listen_ip": "0.0.0.0",
  "listen_port": "443",
  "tcp_fast_open": true,
  "transportProtocol": {
    "type": "grpc",
    "settings": {
      "service_name": "tld"
    }
  },
  //vless
  "flow": "xtls-rprx-vision",
  // shadowsocks
  "cipher": "aes-128-gcm",
  // hysteria
  //obfs_type(salamander or gecko)
  "obfs_type": "salamander",
  "obfs_password": "password",
  "geckoMinPacketSize": 512,
  "geckoMaxPacketSize": 1200,
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  "realm_server_url": "",
  "realm_token": "",
  "realm_id": "",
  "realm_stun_servers": [],
  //tuic
  "congestion_control": "bbr",
  //naive
  "enable_quic" : false,
  "quic_congestion_control": "bbr",
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "www.microsoft.com",
  "handshake_server_port": 443
}
```

####  HTTPUPGRADE
```
{
  "listen_ip": "0.0.0.0",
  "listen_port": "443",
  "tcp_fast_open": true,
  "transportProtocol": {
    "type": "httpupgrade",
    "settings": {
      "host": "tld.dev",
      "path": "/"
    }
  },
  //vless
  "flow": "xtls-rprx-vision",
  // shadowsocks
  "cipher": "aes-128-gcm",
  // hysteria
  //obfs_type(salamander or gecko)
  "obfs_type": "salamander",
  "obfs_password": "password",
  "geckoMinPacketSize": 512,
  "geckoMaxPacketSize": 1200,
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  "realm_server_url": "",
  "realm_token": "",
  "realm_id": "",
  "realm_stun_servers": [],
  //tuic
  "congestion_control": "bbr",
  //naive
  "enable_quic" : false,
  "quic_congestion_control": "bbr",
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "www.microsoft.com",
  "handshake_server_port": 443
}
```

### Security Settings

#### TLS / REALITY
```
{
  "tlsSettings": {
    "enabled": true,
    "insecure": false,
    "cert_mode": "http",
    "server_name": "tld.dev",
	"spoof": "",
    "spoof_method": "",
    "alpn": [
      "h2",
      "http/1.1"
    ],
    "ech": {
      "enabled": false,
      "key": [],
      "config": [],
      "query_server_name": ""
    },
    "reality": {
      "enabled": false,
      "short_ids": [],
      "private_key": "",
      "public_key": "",
      "handshake_server": "www.microsoft.com",
      "handshake_server_port": "443"
    }
  }
}
```

# XMBox Commands Reference

## Basic Operations

| Command | Description |
|---------|-------------|
| `XMBox` | Show menu (more features) |
| `XMBox start` | Start XMBox |
| `XMBox stop` | Stop XMBox |
| `XMBox restart` | Restart XMBox |
| `XMBox status` | View XMBox status |

## Service Management

| Command | Description |
|---------|-------------|
| `XMBox enable` | Enable XMBox auto-start |
| `XMBox disable` | Disable XMBox auto-start |

## Logging & Configuration

| Command | Description |
|---------|-------------|
| `XMBox log` | View XMBox logs |
| `XMBox config` | Show configuration file content |

## Installation & Updates

| Command | Description |
|---------|-------------|
| `XMBox install` | Install XMBox |
| `XMBox uninstall` | Uninstall XMBox |
| `XMBox update` | Update XMBox |
| `XMBox update vx.x.x` | Update XMBox to specific version |
| `XMBox version` | View XMBox version |

## Key Generation & Utilities

| Command | Description |
|---------|-------------|
| `XMBox x25519` | Generate key pairs for X25519 key exchange (REALITY) |
| `XMBox ech` | Generate ECH keys pairs with default or custom server name |