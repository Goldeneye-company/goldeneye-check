#!/bin/sh
# Limits access to the published GHALAM ports (80, 443) to a list of internal subnets.
# Needed because Docker publishes ports around ufw: ufw rules do not apply to them.
# The rules go into the DOCKER-USER chain, which Docker does not overwrite.
#
# Settings are in /etc/default/ghalam-firewall:
#   GHALAM_IFACE=ens18
#   GHALAM_ALLOWED_NETS="192.168.74.0/24 10.10.0.0/16"
set -eu

[ -f /etc/default/ghalam-firewall ] && . /etc/default/ghalam-firewall
: "${GHALAM_IFACE:?Set GHALAM_IFACE in /etc/default/ghalam-firewall}"
: "${GHALAM_ALLOWED_NETS:?Set GHALAM_ALLOWED_NETS in /etc/default/ghalam-firewall}"

iptables -N DOCKER-USER 2>/dev/null || true
iptables -F DOCKER-USER
iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN

for port in 80 443; do
    for net in $GHALAM_ALLOWED_NETS; do
        iptables -A DOCKER-USER -i "$GHALAM_IFACE" -s "$net" -p tcp \
            -m conntrack --ctorigdstport "$port" --ctdir ORIGINAL -j RETURN
    done
    iptables -A DOCKER-USER -i "$GHALAM_IFACE" -p tcp \
        -m conntrack --ctorigdstport "$port" --ctdir ORIGINAL -j DROP
done

iptables -A DOCKER-USER -j RETURN
echo "DOCKER-USER: access to 80/443 through $GHALAM_IFACE is allowed only for: $GHALAM_ALLOWED_NETS"
