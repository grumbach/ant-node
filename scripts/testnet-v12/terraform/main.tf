# v12 storage-bound audit verification testnet.
#
# 5 worker droplets (s-8vcpu-16gb, 80 nodes each = 400 services) +
# 1 monitoring droplet (s-2vcpu-4gb) + 1 client droplet (s-2vcpu-4gb) +
# 1 EVM droplet (s-2vcpu-4gb) running a local Anvil chain so payment
# verification runs against a local EVM instead of Arbitrum mainnet.
# All on DigitalOcean. ~$20 per 24h run at on-demand prices (well under
# that for a 4h run).
#
# Outputs the IP list a downstream bash script consumes.

terraform {
  required_version = ">= 1.5"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

variable "do_token" {
  description = "DigitalOcean API token. Pass via TF_VAR_do_token env var; never check in."
  type        = string
  sensitive   = true
}

variable "ssh_key_fingerprint" {
  description = "Fingerprint of an SSH key already uploaded to your DO account."
  type        = string
}

variable "run_id" {
  description = "Short identifier used as a prefix in droplet names so multiple runs don't collide."
  type        = string
  default     = "v12verify"
}

variable "worker_size" {
  description = "Droplet size for the 5 worker nodes."
  type        = string
  default     = "s-8vcpu-16gb"
}

variable "side_size" {
  description = "Droplet size for monitor + client."
  type        = string
  default     = "s-2vcpu-4gb"
}

# 5 regions for geographic spread within DigitalOcean.
locals {
  worker_regions = {
    "nyc1" = 1
    "sfo3" = 2
    "lon1" = 3
    "ams3" = 4
    "sgp1" = 5
  }
}

provider "digitalocean" {
  token = var.do_token
}

# Worker droplets — 80 ant-node services each, mix of honest + adversary
# per the deploy script's manifest file. UDP firewall port range
# 10000-10999 per the project port-isolation policy.
resource "digitalocean_droplet" "worker" {
  for_each = local.worker_regions

  name     = "${var.run_id}-worker-${each.key}"
  region   = each.key
  size     = var.worker_size
  image    = "ubuntu-24-04-x64"
  ssh_keys = [var.ssh_key_fingerprint]
  tags     = ["v12verify", "worker", "run-${var.run_id}"]

  # Boot-time prep: open file-descriptor limits, install rsync for
  # log collection. The deploy script does the rest.
  user_data = <<-EOT
    #!/bin/bash
    set -e
    apt-get update -y
    apt-get install -y rsync jq build-essential
    cat >> /etc/security/limits.conf <<LIM
    * soft nofile 65535
    * hard nofile 65535
    LIM
    sysctl -w net.core.rmem_max=26214400
    sysctl -w net.core.wmem_max=26214400
    mkdir -p /var/log/ant-nodes
  EOT
}

# Monitoring droplet — log collector + analysis target.
resource "digitalocean_droplet" "monitor" {
  name     = "${var.run_id}-monitor"
  region   = "nyc1"
  size     = var.side_size
  image    = "ubuntu-24-04-x64"
  ssh_keys = [var.ssh_key_fingerprint]
  tags     = ["v12verify", "monitor", "run-${var.run_id}"]

  user_data = <<-EOT
    #!/bin/bash
    set -e
    apt-get update -y
    apt-get install -y rsync jq python3 python3-pip
  EOT
}

# Client droplet — runs workload-gen against the network.
resource "digitalocean_droplet" "client" {
  name     = "${var.run_id}-client"
  region   = "nyc1"
  size     = var.side_size
  image    = "ubuntu-24-04-x64"
  ssh_keys = [var.ssh_key_fingerprint]
  tags     = ["v12verify", "client", "run-${var.run_id}"]

  user_data = <<-EOT
    #!/bin/bash
    set -e
    apt-get update -y
    apt-get install -y rsync jq python3 python3-pip
  EOT
}

# EVM droplet — runs a single local Anvil chain (ant-evm-testnet) with
# the ANT token + payment vault deployed. Every node + the workload
# client point their --evm-rpc-url here so payment verification runs
# against this local chain instead of Arbitrum mainnet. Installs Foundry
# (anvil) at boot.
resource "digitalocean_droplet" "evm" {
  name     = "${var.run_id}-evm"
  region   = "nyc1"
  size     = var.side_size
  image    = "ubuntu-24-04-x64"
  ssh_keys = [var.ssh_key_fingerprint]
  tags     = ["v12verify", "evm", "run-${var.run_id}"]

  user_data = <<-EOT
    #!/bin/bash
    set -e
    apt-get update -y
    apt-get install -y rsync jq curl git
    # Install Foundry (anvil) for the root user so the deploy script's
    # ant-evm-testnet binary can spawn a chain.
    export HOME=/root
    curl -L https://foundry.paradigm.xyz | bash || true
    /root/.foundry/bin/foundryup || true
    ln -sf /root/.foundry/bin/anvil /usr/local/bin/anvil || true
  EOT
}

# Firewall: SSH from anywhere, UDP 10000-10999 across all peers, plus
# inter-droplet rsync for log collection, plus the EVM RPC port.
resource "digitalocean_firewall" "v12verify" {
  name = "${var.run_id}-fw"
  tags = ["v12verify"]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "udp"
    port_range       = "10000-10999"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  # Local-EVM JSON-RPC (Anvil) — reachable by all nodes + the client.
  inbound_rule {
    protocol         = "tcp"
    port_range       = "8545"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "icmp"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# ----------------------------------------------------------------------
# Outputs consumed by deploy/* scripts.
# ----------------------------------------------------------------------

output "worker_ips" {
  description = "IPs of the 5 worker droplets, keyed by region."
  value       = { for r, _ in local.worker_regions : r => digitalocean_droplet.worker[r].ipv4_address }
}

output "monitor_ip" {
  value = digitalocean_droplet.monitor.ipv4_address
}

output "client_ip" {
  value = digitalocean_droplet.client.ipv4_address
}

output "evm_ip" {
  value = digitalocean_droplet.evm.ipv4_address
}
