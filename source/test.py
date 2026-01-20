import socket
import threading

# Ayarlar
LISTEN_PORT = 8881
BUFFER_SIZE = 4096

def handle_client(client_socket):
    try:
        # İstemciden gelen ilk isteği al (Genelde HTTP veya TLS ClientHello)
        data = client_socket.recv(BUFFER_SIZE)
        if not data:
            return

        # Basit bir DPI Bypass tekniği: Paketi parçalara bölerek gönder
        # Örneğin ilk 2 baytı ayrı, geri kalanı ayrı göndermek bazı eski DPI'ları yanıltır.
        part1 = data[:2]
        part2 = data[2:]

        # Gerçek sunucuya bağlan (Örnek olarak bir hedef belirlenmeli)
        # Not: Bu örnek basitleştirilmiştir, gerçek bir proxy host bilgisini okumalıdır.
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect(("target-website.com", 443))

        # Parçalı gönderim
        remote_socket.send(part1)
        remote_socket.send(part2)

        # Karşılıklı veri aktarımı (Röle)
        def relay(src, dst):
            try:
                while True:
                    d = src.recv(BUFFER_SIZE)
                    if not d: break
                    dst.send(d)
            except:
                pass

        threading.Thread(target=relay, args=(client_socket, remote_socket)).start()
        threading.Thread(target=relay, args=(remote_socket, client_socket)).start()

    except Exception as e:
        print(f"Hata: {e}")

def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", LISTEN_PORT))
    server.listen(5)
    print(f"DPI Bypass Proxy {LISTEN_PORT} portunda dinliyor...")
    
    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_sock,)).start()

if __name__ == "__main__":
    start_proxy()
