terraform {
  required_providers {
    digitalocean = {
      source = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
    acme = {
      source = "vancluever/acme"
    }
  }
}
provider "acme" {
  server_url = "https://acme-v02.api.letsencrypt.org/directory"
}

variable "do_token" {}
variable "admin_ssh_keys" {}
variable "fake_flag" {
  type = bool
  default = true
}

locals {
  domain = var.fake_flag ? "movitz.dev" : "tjossan.se"
  part2_subdomain = var.fake_flag ? "aasdsi" : "mate-mate-order-form"
  part3_subdomain = var.fake_flag ? "bboaisjf" : "directorate-of-mate-tasting"
  part4_subdomain = var.fake_flag ? "photos3" : "testshop"

  flag_part1 = var.fake_flag ? "SSM{part1" : "SSM{411_y0"
  flag_part2 = var.fake_flag ? "part2" : "ur_dn5_4r"
  flag_part3 = var.fake_flag ? "part3" : "3_b3lön"
  flag_part4 = var.fake_flag ? "part4}" : "g__t0_u5}"
}

provider "digitalocean" {
  token = var.do_token
}

resource "digitalocean_droplet" "web" {
    name = "tjossan-web"
    image = "ubuntu-22-10-x64"
    region = "fra1"
    size = "s-1vcpu-1gb"
    ssh_keys = var.admin_ssh_keys
}

resource "digitalocean_domain" "tjossanse" {
  name = local.domain
}

resource "tls_private_key" "pkey" {
  algorithm = "RSA"
}

resource "tls_self_signed_cert" "web-cert" {
  private_key_pem = tls_private_key.pkey.private_key_pem
  
  subject {
    common_name = "Tjossan Import/Export"
    country = "Denmark"
    organizational_unit = "Mate Cyber Division"
  }

  dns_names = [ "www.${local.domain}", "${local.part2_subdomain}.${local.domain}"  ]
  allowed_uses = [ "digital_signature", "key_encipherment" ]
  validity_period_hours = 24*30*6
}

resource "acme_registration" "reg" {
  account_key_pem = tls_private_key.pkey.private_key_pem
  email_address   = "not-an-actual-email-i-hope@gmail.com"
}

resource "acme_certificate" "p3-cert" {
  account_key_pem           = acme_registration.reg.account_key_pem
  common_name               = "${local.part3_subdomain}.${local.domain}"

  dns_challenge {
    provider = "digitalocean"
    config = {
      DO_AUTH_TOKEN     = var.do_token
    }
  }
}

resource "digitalocean_record" "webrec" {
  domain = digitalocean_domain.tjossanse.id
  name   = "www"
  type = "A"
  value = digitalocean_droplet.web.ipv4_address
}

resource "digitalocean_record" "part1" {
  domain = digitalocean_domain.tjossanse.id
  name   = "@"
  type = "TXT"
  value = local.flag_part1
}

resource "digitalocean_record" "part2" {
  domain = digitalocean_domain.tjossanse.id
  name   = local.part2_subdomain
  type = "TXT"
  value = local.flag_part2
}

resource "digitalocean_record" "part3" {
  domain = digitalocean_domain.tjossanse.id
  name   = local.part3_subdomain
  type = "TXT"
  value = local.flag_part3
}

resource "digitalocean_record" "part4-A" {
  domain = digitalocean_domain.tjossanse.id
  name   = local.part4_subdomain
  type = "A"
  value = "1.3.3.7"
}


resource "digitalocean_record" "part4" {
  domain = digitalocean_domain.tjossanse.id
  name   = local.part4_subdomain
  type = "TXT"
  value = local.flag_part4
}

resource "local_file" "ansible_vars" {
  content = <<-EOF
    domain: ${digitalocean_record.webrec.fqdn}
    webip: ${digitalocean_droplet.web.ipv4_address}
    EOF
  filename = "./terraform_output/ansible_vars.yml"
}

resource "local_file" "pem" {
  content = tls_self_signed_cert.web-cert.cert_pem
  filename = "./terraform_output/cert/website.pem"
}

resource "local_file" "key" {
  content = tls_self_signed_cert.web-cert.private_key_pem
  filename = "./terraform_output/cert/website.pem.key"
}


resource "local_file" "ansible_inventory" {
  content = <<-EOF
all:
  hosts:
    ${digitalocean_droplet.web.ipv4_address}:
EOF
  filename = "./terraform_output/inventory.yml"
}