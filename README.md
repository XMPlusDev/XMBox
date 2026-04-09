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
DnsFile: /etc/XMBox/dns.json 
RouteFile: /etc/XMBox/route.json 
Log:
  Level: info                                   # debug | info | warn | error
  Disabled: true                                # true, flase
  Output:                                       #/etc/XMBox/output.log
Ntp:
    Enable: false
    Server: time.cloudflare.com
    ServerPort: 53
Multiplex:                                
    Enabled: true                               # true, flase
    Padding: true                               # true, flase
Nodes:
  -
    ApiConfig:
      ApiHost: "https://www.xyz.com"            # Panel api address https://api.tld.com
      ApiKey: "123"                             # Panel server api key
      NodeID: 1                                 # Server (Node) id of the server to connect
      Timeout: 30                               # Timeout for backened server to get response from panel api 
    CertConfig:
      Email: author@cert.xyz                    # Required when Cert Mode is not none
      CertFile: /etc/XMBox/node1.crt            # Required when Cert Mode is file
      KeyFile: /etc/XMBox/node1.key             # Required when Cert Mode is file
      Provider: cloudflare                      # Required when Cert Mode is dns
      CertEnv:                                  # Required when Cert Mode is dns
        CLOUDFLARE_EMAIL:                       # Required when Cert Mode is dns
        CLOUDFLARE_API_KEY:                     # Required when Cert Mode is dns
    RedisConfig:
      Enable: false                             # Enable the global ip limit of a user
      Network: tcp                              # Redis protocol, tcp or unix
      Addr: 127.0.0.1:6379                      # Redis server address, or unix socket path
      Username:                                 # Redis username
      Password:                                 # Redis password
      DB: 0                                     # Redis DB
      Timeout: 10                               # Timeout for redis request
```

## XMPlus Panel Server configuration

### Network Settings

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
  "obfs_type": "salamander",
  "obfs_password": "password"
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  //tuic
  "congestion_control": "bbr"
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "google.com",
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
        "host": "www.baidu.com",
		"method": "GET"
      }
    }
  },
  //vless
  "flow": "xtls-rprx-vision",
  // shadowsocks
  "cipher": "aes-128-gcm",
  // hysteria
  "obfs_type": "salamander",
  "obfs_password": "password"
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  //tuic
  "congestion_control": "bbr"
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "google.com",
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
  "obfs_type": "salamander",
  "obfs_password": "password"
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  //tuic
  "congestion_control": "bbr"
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "google.com",
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
  "obfs_type": "salamander",
  "obfs_password": "password"
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  //tuic
  "congestion_control": "bbr"
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "google.com",
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
  "obfs_type": "salamander",
  "obfs_password": "password"
  "bbr_profile": "standard",
  "ignore_client_bandwidth": true,
  //tuic
  "congestion_control": "bbr"
  //anytls
  "padding_scheme": [],
  //shadowtls
  "strict_mode": false,
  "handshake_server": "google.com",
  "handshake_server_port": 443
}
```

### Security Settings

#### TLS / REALITY
```
{
  "tlsSettings": {
    "enabled: true,
    "insecure": false,
    "alpn": ["h2", "http/1.1"],
    "cert_mode": "http",
    "server_name": "google.com",
	"fragment": false,
	"record_fragment": false,
    "ech": {
	  "enabled: false,
	  "key" [],
	  "config": [],
	  "query_server_name": ""
	},
	"reality": {
	  "enabled: false,
	  "short_ids": [],
	  "private_key": "",
	  "public_key": "",
	  "server_name": "www.microsoft.com",
	  "server_port" "443"
	}
  },
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