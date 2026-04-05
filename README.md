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

## 🧠 Çalışma Mantığı

TriedScan, büyük ölçekli ağ taramalarını yönetmek için "Parçala ve Yönet" (Divide and Conquer) prensibini kullanır.

### 1. IP Bloklarının Parçalanması (Chunking)
Kullanıcı bir IP bloğu girdiğinde (örn: 192.168.1.0/24), sistem şu adımları izler:
* **IP Listeleme:** Nmap'in `-sL` (list scan) özelliği kullanılarak hedef blok, taranabilir tekil IP adreslerinden oluşan temiz bir listeye dönüştürülür.
* **Round-Robin Dağıtımı:** Elde edilen IP listesi, ardışık olarak değil, bir iskambil kağıdı dağıtır gibi işçilere (workers) paylaştırılır. Bu yöntem, yükü dengeler ve ardışık IP tarama alarmlarını (IDS/IPS) atlatmaya yardımcı olur.

### 2. Go Eşzamanlılık Araçlarının Kullanımı
* **Goroutines:** Her bir işçi, Go'nun goroutine yapısı sayesinde birbirinden bağımsız ve paralel olarak başlatılır.
* **sync.WaitGroup:** Tüm asenkron süreçlerin senkronizasyonu için kullanılır. Tüm goroutine'ler işini bitirmeden "Sonuç Birleştirme" aşamasına geçilmez.
* **os/exec:** Nmap ve RustScan, Go'nun `os/exec` kütüphanesi aracılığıyla "alt süreç" olarak çağrılır ve çıktıları anlık olarak yakalanır.

### 3. Gerçek Zamanlı Veri Akışı (SSE)
Go backend'i, her bir alt süreçten gelen logları yakalarken **Server-Sent Events (SSE)** teknolojisini kullanır. Bu sayede tarama sonuçları bittikten sonra değil, Nmap satır satır çıktı ürettikçe Dashboard'a yansıtılır.

---

## 🚀 Öne Çıkan Özellikler

* **Dinamik Sweet Spot Algoritması:** Sistem kaynaklarını ve ağ kalitesini tarama başında analiz ederek en uygun eşzamanlı süreç sayısını belirler.
* **Tam Zamanlı Asenkron Mimari:** İşçiler sıralı değil, Go goroutine altyapısı sayesinde paralel olarak aynı anda başlatılır.
* **Canlı SSE Log Akışı:** Her bir alt sürecin (subprocess) çıktısı, Server-Sent Events (SSE) teknolojisi ile anlık olarak Dashboard'a aktarılır.
* **Otomatik Sonuç Birleştirme (Merging):** Farklı işçilerden gelen ayrı XML çıktılarını, Nmap'in mantıksal yapısını bozmadan tek bir rapor halinde birleştirir.
* **Vakum Temizleyici:** Tarama bittiğinde veya iptal edildiğinde oluşan geçici dosyaları otomatik olarak temizleyerek sistemde çöp bırakmaz.

---

---

## 🛠 Kullanılan Teknolojiler

* **Backend:** Go (Golang) - Yüksek performanslı asenkron süreç yönetimi.
* **Frontend:** HTML5, CSS3 (JetBrains Mono & Oxanium fontları), Vanilla JavaScript.
* **İletişim:** REST API & Server-Sent Events (SSE).
* **Araçlar:** Nmap , RustScan.

---

## 📋 Gereksinimler

Aracın çalışması için sisteminizde (tercihen Kali Linux) şu araçların kurulu olması gerekir:

* Go (Golang) 1.20+
* Nmap
* RustScan

---

## ⚙️ Kurulum ve Çalıştırma

1.  **Depoyu klonlayın:**
    ```bash
    git clone https://github.com/ufuk888/Triedscan.git
    cd Triedscan
    ```
2.  **Gerekli Go modüllerini yükleyin:**
    ```bash
    go mod tidy
    ```
3.  **Uygulamayı başlatın:**
    ```bash
    go run main.go
    ```
4.  **Dashboard'a erişin:**
    Tarayıcınızdan `http://localhost:8080` adresine giderek arayüzü açın.

---

## 📖 Kullanım Kılavuzu

* **Target:** Taramak istediğiniz IP bloğunu (örn: `192.168.1.0/24`) girin.
* **Nmap Arguments:** Kullanmak istediğiniz Nmap parametrelerini seçin (örn: `-sV -A`).
* **Workers:** Otomatik hesaplama için boş bırakın veya manuel bir sayı girin.
* **Engine:** Sadece Nmap veya hibrit (RustScan + Nmap) modunu seçin.
* **Launch Scan:** Taramayı başlatın ve alttaki kutucuklardan işçilerin durumunu canlı izleyin.
