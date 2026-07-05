# Analiza și implementarea protocoalelor criptografice folosite de IKEv2 și IPsec

## Descriere generală

Acest repository conține materialele aferente lucrării de licență **„Analiza și implementarea protocoalelor criptografice folosite de IKEv2 și IPsec”**.

Lucrarea urmărește analiza și implementarea nucleului criptografic al protocoalelor folosite în IKEv2 și IPsec-ESP. Scopul nu este reproducerea completă a standardelor IKEv2 și IPsec, ci modelarea mecanismelor esențiale de securitate: autentificarea participanților, stabilirea cheilor de sesiune, derivarea materialului criptografic și protecția datelor prin criptare autentificată.

Implementarea a fost realizată folosind platforma **SJAKE**, un framework Java destinat implementării și analizei experimentale a protocoalelor de tip AKE.

---

## Obiectivele lucrării

Principalele obiective ale lucrării au fost:

* identificarea nucleului criptografic al protocoalelor IKEv2 și IPsec-ESP;
* implementarea unor protocoale simplificate, dar relevante din punct de vedere al securității;
* testarea funcțională a protocoalelor implementate;
* compararea performanțelor variantelor MAC-PSK și SIG-PKC;
* implementarea unor atacuri Interleaving asupra variantelor vulnerabile;
* evidențierea diferenței dintre folosirea unor primitive criptografice sigure și proiectarea unui protocol sigur ca ansamblu.

---

## Protocoale implementate

În cadrul lucrării au fost implementate trei protocoale principale:

| Protocol                  | Rol                              | Caracteristici principale                                                                           |
| ------------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------- |
| `MAKE-IKE-SIG-PKC-DHE 4M` | Stabilirea cheilor în stil IKEv2 | 4 mesaje, Diffie-Hellman efemer, semnături digitale, certificate, mesaje Auth protejate             |
| `MAKE-IKE-MAC-PSK-DHE 4M` | Stabilirea cheilor în stil IKEv2 | 4 mesaje, Diffie-Hellman efemer, autentificare prin MAC și cheie pre-partajată                      |
| `MAKE-ESP-MAC-PSK-DHE 2M` | Modelarea comportamentului ESP   | 2 mesaje, protejarea datelor de inițializare în `eData`, derivare de chei pentru transfer securizat |

---

## Platforma SJAKE

SJAKE a fost folosită ca infrastructură experimentală pentru implementarea și testarea protocoalelor. Platforma permite:

* definirea participanților onești, precum Ana și Bob;
* modelarea unui adversar activ;
* transmiterea și procesarea mesajelor de protocol;
* utilizarea primitivelor criptografice din Java Cryptography Architecture;
* afișarea trace-urilor de execuție;
* rularea variantelor corecte și vulnerabile;
* măsurarea timpilor de execuție pentru diferite configurații criptografice.

Un aspect important al platformei este faptul că permite observarea concretă a execuției unui protocol: mesajele transmise, stările interne, verificările criptografice și momentul în care protocolul ajunge în starea `ESTABLISHED`.

---

## Elemente specifice ale lucrării

Lucrarea nu se limitează la implementarea unor protocoale AKE generice. Elementele specifice sunt:

### 1. Negocierea autentificată a algoritmilor criptografici

Modelul implementat este simplificat față de IKEv2, deoarece fiecare participant transmite o singură configurație criptografică, nu o listă completă de propuneri. Totuși, partea importantă de securitate este păstrată: algoritmul ales este inclus în autentificator.

Astfel, un adversar nu poate modifica parametrii criptografici fără ca verificarea autentificatorului să eșueze.

### 2. Date inițiale protejate în mesajele `Auth`

Mesajele `Auth` includ date inițiale protejate prin criptare autentificată. Aceste date modelează informații care, într-un protocol IKEv2 complet, ar fi necesare pentru stabilirea asocierilor de securitate `IKE SA` și `ESP SA`.

Prin această abordare, unele detalii funcționale sunt simplificate, dar cerința de securitate rămâne: datele importante sunt transmise protejat.

### 3. Ascunderea identității participanților

În protocolul `MAKE-IKE-SIG-PKC-DHE 4M`, identitatea criptografică este ascunsă prin transmiterea certificatului în partea criptată a mesajului `Auth`.

Pentru varianta `MAKE-IKE-MAC-PSK-DHE 4M`, ascunderea completă a identității nu a putut fi realizată, deoarece platforma SJAKE nu separă adresa de comunicație de numele participantului. Aceasta reprezintă o limitare a platformei, nu a principiului criptografic analizat.

---

## Testare funcțională

Protocoalele implementate au fost testate în scenarii cu doi participanți onești, Ana și Bob. Testarea a urmărit:

* transmiterea mesajelor în ordinea corectă;
* verificarea autentificatorilor;
* derivarea cheilor de sesiune;
* trecerea participanților în starea `ESTABLISHED`;
* folosirea cheilor rezultate pentru transmiterea de date protejate.

Rezultatele au confirmat faptul că protocoalele corecte produc sesiuni criptografice funcționale și permit comunicație securizată după finalizarea schimbului de chei.

---

## Analiza performanțelor

Pentru analiza performanțelor au fost comparate variantele `MAC-PSK` și `SIG-PKC`, folosind configurații criptografice diferite.

| Protocol                  | Configurație          | Timp mediu |
| ------------------------- | --------------------- | ---------: |
| `MAKE-IKE-MAC-PSK-DHE 4M` | `ECDH_256_CTR_128`    |  `3.73 ms` |
| `MAKE-IKE-MAC-PSK-DHE 4M` | `DH_3072_CTR_128`     |  `5.34 ms` |
| `MAKE-IKE-SIG-PKC-DHE 4M` | `ECDH_256_CTR_128`    |  `9.13 ms` |
| `MAKE-IKE-SIG-PKC-DHE 4M` | `DH_RSA_3072_CTR_128` | `15.36 ms` |

Rezultatele arată că varianta `MAC-PSK` este mai rapidă decât varianta `SIG-PKC`, deoarece autentificarea prin MAC folosește operații simetrice eficiente. În schimb, `SIG-PKC` presupune operații mai costisitoare, precum semnarea, verificarea semnăturilor și procesarea certificatelor.

Totuși, alegerea mecanismului de autentificare nu trebuie făcută doar pe baza timpului de execuție. `MAC-PSK` este mai rapid și mai simplu, dar `SIG-PKC` este mai potrivit pentru sisteme mari, unde certificatele oferă o administrare mai scalabilă a identităților.

---

## Atacuri asupra variantelor vulnerabile

Lucrarea include și implementarea unor atacuri de tip **Interleaving** asupra variantelor vulnerabile ale protocoalelor `MAC-PSK` și `SIG-PKC`.

În aceste atacuri, adversarul nu sparge primitivele criptografice:

* nu rezolvă problema Diffie-Hellman;
* nu află cheia pre-partajată;
* nu falsifică semnături digitale;
* nu compromite certificate.

Vulnerabilitatea apare deoarece autentificatorul nu acoperă complet transcriptul sesiunii. Astfel, un autentificator valid poate fi reutilizat într-un context greșit.

Atacurile demonstrează că un protocol nu este sigur doar pentru că folosește algoritmi siguri. Este necesar ca identitatea, cheia, sesiunea și transcriptul mesajelor să fie legate corect.

---

## Concluzii

Lucrarea evidențiază faptul că securitatea unui protocol criptografic nu depinde doar de alegerea unor primitive sigure, ci de modul în care acestea sunt integrate în fluxul protocolului.

Prin implementarea, testarea și atacarea experimentală a protocoalelor, lucrarea arată diferența dintre:

* folosirea unor algoritmi criptografici siguri;
* proiectarea unui protocol sigur ca ansamblu.

Concluzia principală este că un protocol devine sigur doar atunci când identitatea, cheia de sesiune, direcția mesajelor și transcriptul complet sunt autentificate și legate corect între ele.

---

## Direcții viitoare

Lucrarea poate fi extinsă prin:

* implementarea unei negocieri criptografice mai apropiate de IKEv2, cu mai multe oferte;
* separarea identității criptografice de adresa de comunicație în SJAKE;
* ascunderea completă a identității și în varianta `MAC-PSK`;
* extinderea protocolului `MAKE-ESP` cu mai multe detalii despre `ESP SA`;
* testarea mai multor configurații criptografice;
* implementarea altor tipuri de atacuri asupra protocoalelor AKE;
* completarea testării experimentale cu metode de verificare formală.

---

## Structura recomandată a repository-ului

```text
.
├── README.md
├── lucrare/
│   └── Licenta_Fierea_Cosmin-Andrei.pdf
├── prezentare/
│   └── Prezentare_Licenta.pdf
├── poster/
│   └── Poster_Licenta.pdf
├── cod-sursa/
│   ├── MAKE-IKE-SIG-PKC-DHE-4M/
│   ├── MAKE-IKE-MAC-PSK-DHE-4M/
│   ├── MAKE-ESP-MAC-PSK-DHE-2M/
│   └── atacuri-ILV/
└── rezultate/
    ├── teste-functionale/
    ├── teste-performanta/
    └── trace-uri-atacuri/
```

---

## Autor

**Fierea M.M. Cosmin-Andrei**
Universitatea Națională de Știință și Tehnologie POLITEHNICA București
Facultatea de Electronică, Telecomunicații și Tehnologia Informației
Specializarea Rețele Software de Telecomunicații


---

## Observație

Acest repository are scop academic și documentează implementarea experimentală a unor protocoale criptografice inspirate din IKEv2 și IPsec-ESP. Implementările sunt destinate analizei și testării în platforma SJAKE și nu reprezintă o implementare completă, interoperabilă, a standardelor IKEv2/IPsec.
