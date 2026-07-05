# Trace — MAKE-ESP-MAC-PSK-DHE 2M

## Test rulat

```text
TEST_2P_MAKE_ESP_MAC_PSK_DH_2M
```

Protocol testat:

```text
MAKE-ESP-MAC-PSK-DHE 2M
```

Acest test verifică execuția protocolului `MAKE-ESP-MAC-PSK-DHE 2M` între doi participanți onești: `ana` și `bob`.

Protocolul modelează, într-o formă simplificată, comportamentul componentei ESP din IPsec. Spre deosebire de protocoalele `MAKE-IKE`, acest protocol nu folosește patru mesaje și nu are mesaje separate de tip `AUTH_A` și `AUTH_B`. Schimbul se realizează în doar două mesaje:

```text
INIT_A → INIT_B
```

Scopul testului este să confirme că protocolul:

* transmite corect mesajele `INIT_A` și `INIT_B`;
* protejează datele de inițializare în câmpul `eData`;
* verifică mesajele protejate prin criptare autentificată;
* extrage datele necesare pentru schimbul Diffie-Hellman;
* derivă chei de sesiune comune;
* ajunge în starea `ESTABLISHED`;
* permite transmiterea de date protejate după finalizarea handshake-ului.

---

## Diferență față de protocoalele MAKE-IKE 4M

Protocoalele `MAKE-IKE-SIG-PKC-DHE 4M` și `MAKE-IKE-MAC-PSK-DHE 4M` folosesc patru mesaje:

```text
INIT_A → INIT_B → AUTH_A → AUTH_B
```

În schimb, protocolul `MAKE-ESP-MAC-PSK-DHE 2M` folosește doar două mesaje:

```text
INIT_A → INIT_B
```

Datele care în alte protocoale apar explicit în mesajele de inițializare sunt introduse aici în câmpul protejat `eData`.

Prin această abordare, protocolul urmărește ideea principală a componentei ESP: protecția datelor prin mecanisme criptografice, folosind material de cheie derivat în urma schimbului.

---

## Etapele principale ale trace-ului

### 1. Ana inițiază protocolul

Trace-ul începe cu sesiunea Anei în starea:

```text
state START
```

Ana construiește mesajul `INIT_A`:

```text
[KeyEx: ana] build InitMsg to bob, new state INIT_SENT
[Comm] MsgHeader: { INIT_A from ana to bob sid 0F158E91D2E6CDD3 }
```

După trimiterea mesajului, Ana trece în starea:

```text
INIT_SENT
```

În acest protocol, mesajul `INIT_A` nu afișează în clar nonce-ul, cheia publică Diffie-Hellman și algoritmul. Aceste informații sunt introduse în câmpul:

```text
eData
```

Trace-ul arată că `INIT_A` conține:

```text
eData
data
IV
mac
```

Acest lucru indică faptul că datele de inițializare sunt protejate prin criptare autentificată.

---

### 2. Rolul câmpului `eData`

Câmpul `eData` este elementul central al protocolului `MAKE-ESP-MAC-PSK-DHE 2M`.

În interiorul lui sunt protejate datele necesare pentru inițializarea sesiunii, precum:

* configurația criptografică;
* nonce-ul participantului;
* valoarea publică Diffie-Hellman.

Aceste date nu sunt transmise direct în clar, ci sunt codificate și protejate criptografic.

În trace, structura mesajului apare astfel:

```text
eData[234]:
  data[154]
  IV[16]
  mac[64]
```

Această structură arată că mesajul conține:

* `data` — conținutul criptat;
* `IV` — vectorul de inițializare folosit la criptare;
* `mac` — codul de autentificare folosit pentru verificarea integrității.

Dacă un adversar ar modifica datele din `eData`, verificarea criptografică ar eșua, iar mesajul nu ar fi acceptat.

---

### 3. Bob primește `INIT_A` și răspunde cu `INIT_B`

Bob primește mesajul `INIT_A` în starea `START`:

```text
[KeyEx: bob] recv InitMsg in state START
```

După verificarea și procesarea mesajului primit, Bob construiește mesajul `INIT_B`:

```text
[KeyEx: bob] build InitMsg to ana, new state INIT_SENT
[Comm] MsgHeader: { INIT_B from bob to ana sid 0F158E91D2E6CDD3 }
```

Mesajul `INIT_B` are aceeași structură ca `INIT_A`. Și acesta conține un câmp `eData` protejat:

```text
eData[234]:
  data[154]
  IV[16]
  mac[64]
```

În `INIT_B`, Bob transmite propriile date de inițializare într-o formă criptată și autentificată.

---

### 4. Bob finalizează handshake-ul

După construirea și trimiterea mesajului `INIT_B`, Bob finalizează protocolul:

```text
[KeyEx: bob] Responder: handshake done, state ESTABLISHED. Success
```

Acest lucru arată că, din perspectiva responderului, mesajul primit de la Ana a fost valid, datele au putut fi extrase corect, iar cheia de sesiune a fost derivată cu succes.

Bob ajunge în starea:

```text
ESTABLISHED
```

---

### 5. Ana primește `INIT_B` și finalizează protocolul

Ana primește mesajul `INIT_B` în starea `INIT_SENT`:

```text
[KeyEx: ana] recv InitMsg in state INIT_SENT
```

După verificarea câmpului `eData`, Ana finalizează handshake-ul:

```text
[KeyEx: ana] Initiator: handshake done, state ESTABLISHED. Success
```

Această etapă confirmă că Ana a verificat mesajul lui Bob, a extras datele necesare și a derivat aceeași cheie de sesiune.

---

## Starea finală a sesiunilor

Trace-ul confirmă că ambele sesiuni au ajuns în starea `ESTABLISHED`:

```text
[Party: ana] 1 sessions
Session[0]: sid 0F158E91D2E6CDD3 from ana to bob state ESTABLISHED

[Party: bob] 1 sessions
Session[0]: sid 0F158E91D2E6CDD3 from bob to ana state ESTABLISHED
```

Acesta este rezultatul așteptat pentru o execuție corectă a protocolului.

Starea `ESTABLISHED` indică faptul că Ana și Bob au finalizat schimbul de mesaje, au verificat datele protejate și au obținut material criptografic utilizabil pentru protecția comunicației.

---

## Testarea comunicației după handshake

După finalizarea schimbului de chei, sistemul devine pregătit pentru comunicație:

```text
>> System ready for communications <<
```

Ana trimite un mesaj de date către Bob:

```text
Party[ana]: sends message to bob
[Comm] MsgHeader: { DATA from ana to bob sid 0F158E91D2E6CDD3 }
```

Mesajul este transmis ca `AE_DATA`, ceea ce arată că datele sunt protejate prin criptare autentificată.

Trace-ul afișează componentele mesajului protejat:

```text
AE_DATA
IV
mac
```

Bob primește și acceptă mesajul:

```text
Party[bob]: rcvd message from ana (ana). Accepted
```

Apoi Bob trimite un mesaj către Ana:

```text
Party[bob]: sends message to ana
[Comm] MsgHeader: { DATA from bob to ana sid 0F158E91D2E6CDD3 }
```

Și acest mesaj este protejat ca `AE_DATA`.

Ana primește și acceptă mesajul:

```text
Party[ana]: rcvd message from bob (bob). Accepted
```

Această etapă confirmă că materialul criptografic rezultat după handshake este folosit efectiv pentru protejarea comunicației în ambele direcții.

---

## Observație despre rolul ESP

Protocolul `MAKE-ESP-MAC-PSK-DHE 2M` nu implementează pachetul ESP complet din IPsec. Nu sunt modelate toate câmpurile unui pachet ESP real și nici toate detaliile operaționale ale standardului.

În schimb, protocolul modelează nucleul criptografic al comportamentului ESP:

* date protejate prin criptare autentificată;
* folosirea unei chei pre-partajate pentru protecția inițială;
* schimb Diffie-Hellman pentru obținerea materialului criptografic;
* derivarea cheilor de sesiune;
* folosirea acestor chei pentru protecția datelor transmise.

Astfel, protocolul arată cum poate fi obținut și folosit material criptografic pentru comunicație securizată într-un model inspirat de ESP.

---

## Concluzie

Trace-ul confirmă execuția corectă a protocolului `MAKE-ESP-MAC-PSK-DHE 2M`.

Rezultatele importante sunt:

* protocolul folosește doar două mesaje: `INIT_A` și `INIT_B`;
* datele de inițializare sunt protejate în câmpul `eData`;
* mesajele conțin date criptate, vector de inițializare și cod de autentificare;
* Bob ajunge în starea `ESTABLISHED` după procesarea mesajului Anei și trimiterea răspunsului;
* Ana ajunge în starea `ESTABLISHED` după primirea și verificarea mesajului lui Bob;
* datele transmise după handshake sunt protejate prin `AE_DATA`;
* comunicația este acceptată cu succes în ambele direcții.

Testul demonstrează că protocolul `MAKE-ESP-MAC-PSK-DHE 2M` produce material criptografic utilizabil și permite transmiterea de date protejate după finalizarea schimbului de mesaje.
