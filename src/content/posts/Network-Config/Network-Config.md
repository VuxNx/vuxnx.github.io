---
title: Network tunnel configuration guide for VM and VPS
published: 2025-09-24
description: ''
image: ''
tags: [network]
category: 'Guide'
draft: false 
lang: 'vi'
---

## Prequisites

Để tiến hành các bước setup trên VM và VPS, chúng ta cần những thứ sau đây:
1. Một bản clone của Kali image đang sử dụng (sẽ có các bước điều chỉnh sau đó). Clone ra để tránh máy chính bị compromised 😐.
2. Máy host đang kết nối vào LAN thông qua một interface nào đó.
3. Một VPS đóng vai trò là VPN server.

## VM network config

Đối với VM, chúng ta tiến hành điều chỉnh network cho VM lần lượt theo các bước sau đây:
1. Trong ```Network Adapter``` của VM, ta chọn ```Network connection``` là ```Bridged``` và tick ```Replicate physical network connection state``` (ảnh dưới). Sau đó ấn ```OK```.
![Bridge](./bridge.png)
2. Tiếp đó, ta cần vào ```Virtual Network Editor``` (vào bằng quyền admin) để edit lại config của ```VMnet0``` (nếu không có thì bấm vào ```Add network```, chọn ```VMnet0```). Đến đây ta tiếp tục chọn ```Bridged```. Trong ```Bridged to```, ta chọn ```interface``` mà host đang kết nối (có thể thông qua card wifi hay thông qua LAN, cái này đến đây hỏi GPT để nó guide tiếp cách xem và setup). Ấn ```apply``` và ```OK``` để nó load lại config cho con VM (ảnh dưới).
![VNE](./VNE.png)

Như vậy bước đầu của config VM đã xong, tiếp theo ta tiến hành khởi động VM để cấu hình VM thành 1 Jump router.

## Jump router config

1. Cài đặt WireGuard + tạo cấu hình wg0 trên kali VM
```bash
sudo apt update
sudo apt install -y wireguard

umask 077
wg genkey | sudo tee /etc/wireguard/kali.key | wg pubkey | sudo tee /etc/wireguard/kali.pub
echo "KALI_PUB=$(sudo cat /etc/wireguard/kali.pub)"
```

Ghi lại ```KALI_PUB``` để lát dán và config file của VPS.

2. Tạo file ```/etc/wireguard/wg0.conf``` trên Kali VM:
```bash
KALI_PRIV=$(sudo cat /etc/wireguard/kali.key)
sudo bash -c "cat > /etc/wireguard/wg0.conf" <<EOF
[Interface]
Address = 10.7.0.2/24
PrivateKey = ${KALI_PRIV}
# Bật forward khi wg0 lên
PostUp = sysctl -w net.ipv4.ip_forward=1
PostDown = true

[Peer]
# VPS
PublicKey = <PUBLIC_KEY_VPS>
Endpoint = <VPS_PUBLIC_IP>:51820
AllowedIPs = 10.7.0.0/24
PersistentKeepalive = 25
EOF

sudo chmod 600 /etc/wireguard/wg0.conf /etc/wireguard/kali.key
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
sudo systemctl enable --now wg-quick@wg0
sudo wg
```

Trên đây là config để đặt KALI trong mạng VPN có IP là ```10.7.0.2```. Đây là config trong router máy của VuxNx, do đó thì khi setup về máy của Rikka hay Sufferer thì sẽ lấy các IP khác.

3. Config NAT for KALI
```bash
LAN_IF=eth0

sudo iptables -t nat -A POSTROUTING -o $LAN_IF -s 10.7.0.0/24 -j MASQUERADE

sudo iptables -A FORWARD -i wg0 -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT

sudo apt install -y iptables-persistent
sudo netfilter-persistent save

sudo iptables -t nat -L -n -v

sudo systemctl enable --now ssh
```

Cấu hình trên cho phép các gói từ ```wg0``` đi đến KALI và từ đó thông qua IP table trên KALI để đến LAN. Cẩn thận kiểm tra lại xem ```ufw``` có đang hoạt động hay không, nếu có thì phải thêm rule cho nó.

## VPS / VPN server config

```bash
sudo bash -c "cat > /etc/wireguard/wg0.conf" <<'EOF'
[Interface]
Address = 10.7.0.1/24
ListenPort = 51820
PrivateKey = PLACEHOLDER_SERVER_PRIVATE
PostUp = sysctl -w net.ipv4.ip_forward=1
PostDown = true

# ---- Peer: Kali (jump) ----
[Peer]
PublicKey = <KALI_PUB>
AllowedIPs = 10.7.0.2/32, 192.168.1.0/24
EOF

sudo sed -i "s|PLACEHOLDER_SERVER_PRIVATE|$VPS_PRIV|" /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf /etc/wireguard/server.key
sudo ufw allow 51820/udp
sudo systemctl enable --now wg-quick@wg0
sudo wg
sudo ip route add 192.168.1.0/24 via 10.7.0.2 dev wg0
```

Trong đó lấy ```KALI_PUB``` ở cấu hình trên dán vào đây. Với cấu hình trên thì từ VPS có thể đi thẳng vào LAN thông qua KALI VM.

## SOCKS5 config using gost

Cài đặt Gost để socks5 cho external.
```bash
wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

source ~/.bashrc

go install github.com/go-gost/gost/cmd/gost@latest

sudo cp $HOME/go/bin/gost /usr/local/bin/

gost -V

sudo tee /etc/systemd/system/gost-socks.service >/dev/null <<'EOF'
[Unit]
Description=GOST SOCKS5 on Kali (bind to wg0)
After=network-online.target wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
ExecStart=/usr/local/bin/gost -L socks5://user:pass@10.7.0.2:1080
Restart=always
RestartSec=3
User=root
# Hardening nhẹ
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now gost-socks
sudo systemctl status gost-socks --no-pager

```

Với cấu hình trên thì socks5 sẽ tự động mở mỗi khi KALI VM khởi động.

## Nginx server for Dir listing

```bash
sudo apt update
sudo apt install nginx -y

sudo systemctl enable --now nginx
sudo systemctl status nginx

sudo nano /etc/nginx/sites-available/default

```

Trong khối ```server{}``` tìm phần ```location / {}``` và chỉnh như sau:

```bash
server {
    listen 80;
    server_name _;

    root /var/www/html;

    location / {
        autoindex on;               # bật dir listing
        autoindex_exact_size off;   # hiển thị size dạng human-readable
        autoindex_localtime on;     # hiển thị theo giờ local
    }
}
```
Check xem đã hoạt động đúng chưa:
```bash
sudo nginx -t
sudo systemctl reload nginx
```




