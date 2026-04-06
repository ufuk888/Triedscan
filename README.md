# ⬡ TriedScan

**TriedScan**, büyük ölçekli ağlarda Nmap'in hantal yapısını aşmak ve tarama sürecini otomatize etmek için geliştirilmiş, dağıtık mimariye sahip yeni nesil bir ağ tarama motorudur. Go dilinin eşzamanlılık (concurrency) gücünü kullanarak, port keşif hızını **RustScan** ile, derinlemesine analiz yeteneğini ise **Nmap** ile birleştirir.

---

## 🎯 Projenin Amacı

Geleneksel tarama araçları, geniş IP bloklarında (örneğin /16 veya /24) ya çok yavaş kalmakta ya da agresif tarama yaptığında ağdaki NAT tablolarını şişirerek paket kaybına neden olmaktadır. TriedScan şu amaçlarla geliştirilmiştir:

* **Hız ve İsabet Oranı:** RustScan'in inanılmaz port bulma hızıyla ön keşif yapıp, sadece açık portları Nmap'e devrederek zaman kazanmak.
* **IDS/IPS Atlatma:** IP adreslerini "Round-Robin" (dairesel sıralı) algoritmasıyla işçilere dağıtarak, ağ güvenlik cihazlarının ardışık IP tarama tespit mekanizmalarını şaşırtmak.
* **Dinamik Kaynak Yönetimi:** Sistemin anlık CPU, RAM ve ağ gecikmesini (RTT) analiz ederek, ağı boğmayacak en verimli işçi (worker) sayısını otomatik belirlemek.
* **Yönetilebilir Arayüz:** Terminal karmaşasından kurtulup, tüm süreci modern bir **Web Dashboard** üzerinden canlı olarak izlemek.

---

## 🛡️ Güvenlik Özellikleri

TriedScan, güvenli bir tarama ortamı sağlamak için modern koruma mekanizmalarıyla donatılmıştır:

* **Input Validation:** Hedef IP ve Nmap argümanları Regex ve Whitelist tabanlı sıkı denetimden geçer; Command Injection (RCE) riskleri engellenir.
* **Path Traversal Koruması:** Dosya çıktı işlemleri `./scan_output` dizinine izole edilmiştir; sistem dosyalarına erişim imkansızdır.
* **API Authentication:** Tüm API uç noktaları `X-API-Key` başlığı ile korunur. Anahtarlar oturum bazlı saklanır ve disk üzerine yazılmaz.
* **Localhost Isolation:** Sunucu varsayılan olarak `127.0.0.1` üzerinden dinleme yapar, dış dünyaya kapalıdır.

---

## 🧠 Çalışma Mantığı

TriedScan, büyük ölçekli ağ taramalarını yönetmek için "Parçala ve Yönet" (Divide and Conquer) prensibini kullanır.

1. **IP Bloklarının Parçalanması:** Nmap `-sL` ile hedef blok tekil IP listesine dönüştürülür ve Round-Robin algoritmasıyla işçilere paylaştırılır.
2. **Go Eşzamanlılık Araçları:** Her işçi bir **Goroutine** olarak paralel çalışır. **sync.WaitGroup** ile süreç koordinasyonu sağlanır.
3. **Gerçek Zamanlı Veri Akışı:** Alt süreç (subprocess) çıktıları **Server-Sent Events (SSE)** teknolojisi ile anlık olarak Dashboard'a aktarılır.

---

## 🚀 Öne Çıkan Özellikler

* **Dinamik Sweet Spot Algoritması:** Sistem kaynaklarını analiz ederek en uygun eşzamanlı işçi sayısını belirler.
* **Tam Zamanlı Asenkron Mimari:** İşçiler Go goroutine altyapısı sayesinde birbirini beklemeden paralel başlar.
* **Otomatik Sonuç Birleştirme:** Farklı işçilerden gelen XML çıktılarını mantıksal yapıyı bozmadan tek bir raporda birleştirir.
* **Vakum Temizleyici:** Tarama bittiğinde geçici XML dosyalarını otomatik temizleyerek sistemde çöp bırakmaz.

---

## 🛠 Kullanılan Teknolojiler

* **Backend:** Go (Golang) - Yüksek performanslı asenkron süreç yönetimi.
* **Frontend:** HTML5, CSS3 (JetBrains Mono & Oxanium fontları), Vanilla JavaScript.
* **İletişim:** REST API & Server-Sent Events (SSE).
* **Araçlar:** Nmap, RustScan.

---

## 📋 Gereksinimler

Aracın çalışması için sisteminizde (tercihen Kali Linux) şu araçların kurulu olması gerekir:

* Go (Golang) 1.20+
* Nmap
* RustScan
---

## ⚙️ Kurulum ve Çalıştırma

Aşağıdaki adımları terminalinizde sırasıyla çalıştırarak uygulamayı ayağa kaldırabilirsiniz:

```bash
# 1. Depoyu klonlayın ve içine girin
git clone https://github.com/ufuk888/Triedscan.git
cd Triedscan

# 2. Gerekli Go modüllerini yükleyin
go mod tidy

# 3. Uygulamayı başlatın
go run cmd/triedscan/main.go
```

## 📖 Kullanım Kılavuzu

Target: Taramak istediğiniz IP bloğunu (örn: 192.168.1.0/24) girin.

Nmap Arguments: Kullanmak istediğiniz parametreleri seçin (örn: -sV -A).

Workers: Otomatik hesaplama için boş bırakın veya manuel bir sayı girin.

Engine: Sadece Nmap veya hibrit (RustScan + Nmap) modunu seçin.

    Launch Scan: Taramayı başlatın ve alttaki kutucuklardan işçilerin durumunu canlı izleyin.
