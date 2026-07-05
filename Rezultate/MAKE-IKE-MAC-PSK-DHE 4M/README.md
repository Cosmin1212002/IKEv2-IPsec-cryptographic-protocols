# Trace — MAKE-IKE-MAC-PSK-DHE 4M

## Test rulat

```text
TEST_2P_MAKE_IKE_MAC_PSK_DH_4M
```

Protocol testat:

```text
MAKE-IKE-MAC-PSK-DHE 4M
```

Acest test verifică execuția protocolului `MAKE-IKE-MAC-PSK-DHE 4M` între doi participanți onești: `ana` și `bob`.

Scopul testului este să confirme că protocolul:

* schimbă corect mesajele `INIT_A`, `INIT_B`, `AUTH_A` și `AUTH_B`;
* generează valori Diffie-Hellman efemere;
* derivă chei de sesiune comune;
* verifică autentificarea prin MAC folosind o cheie pre-partajată;
* ajunge în starea `ESTABLISHED`;
* permite transmiterea de date protejate după finalizarea handshake-ului.

---

## Configurație criptografică observată în trace

În mesajele `INIT_A` și `INIT_B`, participanții transmit configurația criptografică folosită:

```text
autSec: HMACSHA256[128]
encSec: AES/CTR/NoPadding[128]
dh: ECDH[256]
```

Aceasta arată că testul folosește:

* `ECDH P-256` pentru schimbul Diffie-Hellman;
* `HMACSHA256` pentru autentificarea bazată pe MAC;
* `AES/CTR-128` pentru protecția datelor.

Spre deosebire de protocolul `SIG-PKC`, această variantă nu folosește semnături digitale și certificate. Autentificarea se realizează printr-un MAC calculat cu o cheie secretă pre-partajată.

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
[Comm] MsgHeader: { INIT_A from ana to bob sid 438AADE7D21421EC }
```

Mesajul `INIT_A` conține:

* nonce-ul Anei;
* cheia publică Diffie-Hellman a Anei;
* configurația criptografică propusă.

După trimiterea mesajului, Ana trece în starea:

```text
INIT_SENT
```

Această etapă inițiază schimbul de chei și oferă lui Bob datele necesare pentru continuarea protocolului.

---

### 2. Bob răspunde cu `INIT_B`

Bob primește mesajul `INIT_A` în starea `START`:

```text
[KeyEx: bob] recv InitMsg in state START
```

Apoi construiește mesajul `INIT_B`:

```text
[KeyEx: bob] build InitMsg to ana, new state INIT_RCVD
[Comm] MsgHeader: { INIT_B from bob to ana sid 438AADE7D21421EC }
```

Mesajul `INIT_B` conține:

* nonce-ul lui Bob;
* cheia publică Diffie-Hellman a lui Bob;
* configurația criptografică folosită de Bob.

După schimbul `INIT_A` / `INIT_B`, Ana și Bob au valorile necesare pentru calcularea secretului Diffie-Hellman și pentru derivarea cheilor de sesiune.

---

### 3. Ana construiește mesajul `AUTH_A`

Ana primește mesajul `INIT_B` în starea `INIT_SENT`:

```text
[KeyEx: ana] recv InitMsg in state INIT_SENT
```

Apoi construiește mesajul `AUTH_A`:

```text
[KeyEx: ana] build AuthMsg to bob, new state AUTH_SENT
[Comm] MsgHeader: { AUTH_A from ana to bob sid 438AADE7D21421EC }
```

Mesajul `AUTH_A` nu transmite MAC-ul în clar. Autentificatorul este inclus într-un câmp protejat numit `edata`.

În trace apar componentele:

```text
edata
data
IV
mac
```

Acest lucru arată că mesajul de autentificare este protejat prin criptare autentificată.

În interiorul mesajului sunt protejate:

* autentificatorul MAC al Anei;
* datele inițiale transmise de Ana către Bob.

În această variantă nu apare un certificat, deoarece autentificarea nu se bazează pe infrastructură cu chei publice, ci pe o cheie secretă pre-partajată.

---

### 4. Bob verifică autentificarea Anei

Bob primește `AUTH_A` în starea `INIT_RCVD`:

```text
[KeyEx: bob] recvAuth in state INIT_RCVD
```

Verificarea MAC-ului reușește:

```text
[KeyEx: bob] Successful verification of ana's authenticator (MAC)
Successful authentication: remote user is ana
```

Această etapă confirmă că:

* autentificatorul Anei este valid;
* Bob recunoaște participantul `ana`;
* mesajul `AUTH_A` nu a fost modificat;
* datele protejate au fost decriptate și acceptate corect.

Bob primește și datele inițiale transmise de Ana:

```text
[KeyEx: bob] Received early data: Hello, I'm Ana (the initiator)
```

---

### 5. Bob construiește mesajul `AUTH_B`

După verificarea Anei, Bob construiește mesajul `AUTH_B`:

```text
[KeyEx: bob] build AuthMsg to ana, new state INIT_RCVD
[Comm] MsgHeader: { AUTH_B from bob to ana sid 438AADE7D21421EC }
```

Mesajul `AUTH_B` are aceeași logică precum `AUTH_A`, dar pe direcția Bob către Ana. Și acesta conține un câmp `edata`, format din date criptate autentificat, un vector de inițializare și un cod de autentificare.

După trimiterea mesajului `AUTH_B`, Bob finalizează partea lui de handshake:

```text
[KeyEx: bob] Responder: Auth handshake done, state ESTABLISHED. Success
```

Acest lucru înseamnă că Bob consideră protocolul finalizat cu succes și sesiunea stabilită cu Ana.

---

### 6. Ana verifică autentificarea lui Bob

Ana primește `AUTH_B` în starea `AUTH_SENT`:

```text
[KeyEx: ana] recvAuth in state AUTH_SENT
```

Verificarea autentificatorului lui Bob reușește:

```text
[KeyEx: ana] Successful verification of bob's authenticator (MAC)
Successful authentication: remote user is bob
```

Ana finalizează handshake-ul:

```text
[KeyEx: ana] Initiator: Auth handshake done, state ESTABLISHED. Success
```

Ana primește și datele inițiale transmise de Bob:

```text
[KeyEx: ana] Received early data: Hello, I'm Bob (the responder)
```

Această etapă confirmă autentificarea mutuală: Bob a autentificat-o pe Ana, iar Ana l-a autentificat pe Bob.

---

## Starea finală a sesiunilor

Trace-ul confirmă că ambele sesiuni au ajuns în starea `ESTABLISHED`:

```text
[Party: ana] 1 sessions
Session[0]: sid 438AADE7D21421EC from ana to bob state ESTABLISHED

[Party: bob] 1 sessions
Session[0]: sid 438AADE7D21421EC from bob to ana state ESTABLISHED
```

Acesta este rezultatul așteptat pentru o execuție corectă a protocolului.

Starea `ESTABLISHED` arată că participanții au finalizat schimbul de chei, au verificat autentificatorii și au stabilit o sesiune criptografică validă.

---

## Testarea comunicației după handshake

După finalizarea schimbului de chei, sistemul devine pregătit pentru comunicație:

```text
>> System ready for communications <<
```

Ana trimite un mesaj de date către Bob:

```text
Party[ana]: sends message to bob
[Comm] MsgHeader: { DATA from ana to bob sid 438AADE7D21421EC }
```

Mesajul este transmis ca `AE_DATA`, adică este protejat prin criptare autentificată.

Trace-ul arată componentele:

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
[Comm] MsgHeader: { DATA from bob to ana sid 438AADE7D21421EC }
```

Și acest mesaj este protejat ca `AE_DATA`.

Ana primește și acceptă mesajul:

```text
Party[ana]: rcvd message from bob (bob). Accepted
```

Această etapă confirmă că materialul criptografic derivat în timpul protocolului este folosit efectiv pentru protejarea comunicației de date.

---

## Observație față de varianta SIG-PKC

Comparativ cu protocolul `MAKE-IKE-SIG-PKC-DHE 4M`, varianta `MAC-PSK` are o structură asemănătoare la nivel de flux:

```text
INIT_A → INIT_B → AUTH_A → AUTH_B
```

Diferența principală este mecanismul de autentificare.

În `SIG-PKC`, autentificarea se face prin semnături digitale și certificate. În `MAC-PSK`, autentificarea se face printr-un MAC calculat cu o cheie secretă pre-partajată.

Această diferență se observă și în trace. Mesajele `AUTH_A` și `AUTH_B` din varianta `MAC-PSK` au câmpuri `edata` mai mici, deoarece nu includ certificate și semnături digitale, ci doar autentificatorul MAC și datele inițiale protejate.

---

## Concluzie

Trace-ul confirmă execuția corectă a protocolului `MAKE-IKE-MAC-PSK-DHE 4M`.

Rezultatele importante sunt:

* mesajele `INIT_A` și `INIT_B` sunt transmise corect;
* participanții schimbă nonce-uri și valori publice Diffie-Hellman;
* Ana și Bob derivă chei de sesiune comune;
* mesajele `AUTH_A` și `AUTH_B` sunt protejate prin criptare autentificată;
* autentificarea se realizează cu succes prin MAC și cheie pre-partajată;
* ambii participanți ajung în starea `ESTABLISHED`;
* datele transmise după handshake sunt acceptate în ambele direcții.

Testul demonstrează că protocolul realizează autentificare mutuală prin `MAC-PSK`, stabilește chei de sesiune valide și permite comunicație securizată după finalizarea schimbului de chei.
