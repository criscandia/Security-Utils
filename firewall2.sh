 
# firewall para un solo equipo conectado a traves de modem o adsl


# (1) se eliminan reglas previas que hubiera y cadenas definidas por el usuario
iptables -F
iptables -X

# (2) se establecen politicas "duras" por defecto, es decir solo lo que se autorice
# explicitamente podra ingresar o salir del equipo
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# (3)a la interface lo (localhost) se le permite todo
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# (4) evitamos ataques syn-flood limitando el acceso de paquetes nuevos
# desde internet a solo 4 por segundo y los demas se descartan
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 4 -j DROP

# (5) se evitan paquetes tcp que sean nuevos y que no tengan el flag SYN
# es decir, hay ataques o escaneos que llegan como conexiones nuevas
# pero sin ser paquetes syn, definitivamente no nos interesan
iptables -A INPUT -p tcp --syn -m state --state NEW -j DROP

# (6) todo lo que sea icmp (ping) y que intente entrar, se descarta
# con esto bloqueamos cualquier tipo de paquetes con protocolo icmp
# evitando ataques como el del ping de la muerte, aunque esta regla
# podria provocar problemas de comunicacion con algunos ISP.
iptables -A INPUT -p icmp -j DROP

# (7) por ultimo las dos siguientes reglas permiten salir del equipo 
# (output) conexiones nuevas que nosotros solicitamos, conexiones establecidas
# y conexiones relacionadas, y deja entrar (input) solo conexiones establecidas
# y relacionadas.
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

###OTRAS PROTECCIONES####

# Quitamos los pings.
/bin/echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all

# No respondemos a los broadcast.
/bin/echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Para evitar el spoofing nos aseguramos de que la dirección
# origen del paquete viene del sitio correcto.
for interface in /proc/sys/net/ipv4/conf/*/rp_filter; do
/bin/echo "1" > ${interface}
done

# Los ICMPs redirigidos que pueden alterar la tabla de rutas.
for interface in /proc/sys/net/ipv4/conf/*/accept_redirects; do
/bin/echo "0" > ${interface}
done

# No guardamos registros de los marcianos.
/bin/echo "1" > /proc/sys/net/ipv4/conf/all/log_martians

# Asegurar, aunque no tenga soporte el nucleo, q no hay forward.
/bin/echo "0" > /proc/sys/net/ipv4/ip_forward

###Reglas de los puertos####

# Permitimos que se conecten a nuestro servidor web.

iptables -A INPUT -m state --state NEW -p TCP --dport 80 -j ACCEPT

#Abrimos ssh a la red.

iptables -A INPUT -p TCP --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# Permitimos la comunicación con el servidor dns
iptables -A INPUT -p UDP --dport 53 -j ACCEPT
iptables -A INPUT -p TCP --dport 53 -j ACCEPT

#Permitimos uso de ftp.
iptables -A INPUT -p TCP --dport 21 -j ACCEPT

#Permitimos acceso pop3.
iptables -A INPUT -p TCP --dport 110 -j ACCEPT

# Permitimos uso de smtp
iptables -A INPUT -p TCP --dport 25 -j ACCEPT

#Permitimos acceso imap.
iptables -A INPUT -p TCP --dport 143 -j ACCEPT
iptables -A INPUT -p UDP --dport 143 -j ACCEPT

#Dejamos a localhost, para mysql, etc..
iptables -A INPUT -i lo -j ACCEPT

#Permitimos Git
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -p udp --sport 53 -m state --state ESTABLISHED     -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -p tcp --sport 53 -m state --state ESTABLISHED     -j ACCEPT

# 23. Prevent DoS attack
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
