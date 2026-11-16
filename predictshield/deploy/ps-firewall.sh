#!/bin/bash
# PredictShield firewall helper - manages web-port (80/443) blocks.
# SSH (22) is never touched. Rules tagged "ps-block", inserted at the TOP
# of INPUT (position 1) so they win over the accept-all rules.
ACTION=$1; shift
case "$ACTION" in
  sync)
    while read -r rule; do
      ip=$(echo "$rule" | sed -n "s/.*-s \([^ ]*\).*/\1/p")
      [ -z "$ip" ] && continue
      keep=0
      for w in "$@"; do [ "$w" = "$ip" ] && keep=1; done
      if [ $keep -eq 0 ]; then
        while iptables -D INPUT -s "$ip" -p tcp -m multiport --dports 80,443 -m comment --comment ps-block -j DROP 2>/dev/null; do :; done
      fi
    done < <(iptables -S INPUT 2>/dev/null | grep "ps-block" || true)
    for ip in "$@"; do
      iptables -C INPUT -s "$ip" -p tcp -m multiport --dports 80,443 -m comment --comment ps-block -j DROP 2>/dev/null || iptables -I INPUT 1 -s "$ip" -p tcp -m multiport --dports 80,443 -m comment --comment ps-block -j DROP
    done
    ;;
  block)
    iptables -C INPUT -s "$1" -p tcp -m multiport --dports 80,443 -m comment --comment ps-block -j DROP 2>/dev/null || iptables -I INPUT 1 -s "$1" -p tcp -m multiport --dports 80,443 -m comment --comment ps-block -j DROP
    ;;
  unblock)
    while iptables -D INPUT -s "$1" -p tcp -m multiport --dports 80,443 -m comment --comment ps-block -j DROP 2>/dev/null; do :; done
    ;;
esac
