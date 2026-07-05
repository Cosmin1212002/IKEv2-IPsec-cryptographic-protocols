# Trace — MAKE-MAC-DH-M4-ILV

## Test rulat

```text
TEST_2P_MAKE_MAC_DH_M4_ILV
```

Protocol testat:

```text
MAKE_MAC_DH_M4_ILV
```

Acest test verifică execuția variantei vulnerabile `MAKE_MAC_DH_M4_ILV` între doi participanți onești: `ana` și `bob`.

Important: acest trace nu reprezintă atacul Interleaving propriu-zis. El arată că varianta vulnerabilă poate funcționa corect într-un scenariu normal, fără adversar activ. Vulnerabilitatea apare atunci când un adversar intercalează mesaje din mai multe execuții și profită de faptul că autentificatorul MAC nu acoperă complet transcriptul sesiunii.

---

## Scopul testului

Scopul acestui test este să confirme că protocolul vulnerabil:

* transmite mesajele `INIT_A`, `INIT_B`, `AUTH_A` și `AUTH_B`;
* generează nonce-uri și valori publice Diffie-Hellman;
* verifică autentificatorii MAC folosind o cheie pre-partajată;
* ajunge în starea `ESTABLISHED` când nu există adversar activ;
* permite transmiterea de date protejate după finalizarea handshake-ului.

Acest rezultat este important deoarece arată că protocolul nu eșuează într-o execuție normală. Problema lui nu este funcțională, ci de proiectare criptografică: autentificatorul este valid, dar nu autentifică suficiente date din sesiune.

---

## Diferență față de varianta sigură MAC-PSK

Varianta sigură `MAKE-IKE-MAC-PSK-DHE 4M` protejează mesajele de autentificare prin câmpul `edata`, care include autentificatorul și datele inițiale într-o formă criptată autentificat.

În schimb, în această variantă vulnerabilă, mesajele `AUTH_A` și `AUTH_B` conțin direct câmpul:

```text
auth
```

Acest câmp reprezintă autentificatorul MAC calculat cu cheia pre-partajată.

Diferența importantă nu este doar forma mesajului, ci mai ales conținutul autentificat. În varianta vulnerabilă, MAC-ul nu acoperă complet toate elementele necesare ale sesiunii. Din acest motiv, autentificatorul poate fi valid criptografic, dar insuficient pentru a preveni un atac de tip Interleaving.

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
[Comm] MsgHeader: { INIT_A from ana to bob sid 191B827A95A09EB7 }
```

Mesajul `INIT_A` conține:

* nonce-ul Anei;
* valoarea publică Diffie-Hellman a Anei.

În acest trace, cheia publică Diffie-Hellman are dimensiune mare, ceea ce indică folosirea unei variante clasice de Diffie-Hellman pe grup finit, nu ECDH.

După transmiterea mesajului, Ana trece în starea:

```text
INIT_SENT
```

Această etapă pornește schimbul Diffie-Hellman și oferă lui Bob datele necesare pentru continuarea protocolului.

---

### 2. Bob răspunde cu `INIT_B`

Bob primește mesajul `INIT_A` în starea `START`:

```text
[KeyEx: bob] recv InitMsg in state START
```

Apoi construiește mesajul `INIT_B`:

```text
[KeyEx: bob] build InitMsg to ana, new state INIT_RCVD
[Comm] MsgHeader: { INIT_B from bob to ana sid 191B827A95A09EB7 }
```

Mesajul `INIT_B` conține:

* nonce-ul lui Bob;
* valoarea publică Diffie-Hellman a lui Bob.

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
[Comm] MsgHeader: { AUTH_A from ana to bob sid 191B827A95A09EB7 }
```

Mesajul `AUTH_A` conține câmpul:

```text
auth[32]
```

Acesta reprezintă autentificatorul MAC generat de Ana folosind cheia secretă pre-partajată.

În această variantă vulnerabilă, nu există certificat și nu există semnătură digitală. Autentificarea se bazează exclusiv pe MAC și pe faptul că Ana și Bob cunosc aceeași cheie pre-partajată.

---

### 4. Bob verifică autentificarea Anei

Bob primește `AUTH_A` în starea `INIT_RCVD`:

```text
[KeyEx: bob] recvAuth in state INIT_RCVD
```

Verificarea MAC-ului reușește:

```text
[KeyEx: bob] Successful verification of ana's authenticator (MAC-PSK-DHE-VULN)
Successful authentication: remote user is ana
```

Această etapă confirmă că:

* MAC-ul primit de la Ana este valid;
* Bob autentifică participantul `ana`;
* protocolul continuă normal în absența unui adversar activ.

Totuși, faptul că MAC-ul este valid nu înseamnă automat că protocolul este sigur. Vulnerabilitatea apare deoarece MAC-ul nu include complet elementele care trebuie legate de sesiunea curentă.

---

### 5. Bob construiește mesajul `AUTH_B`

După verificarea Anei, Bob construiește mesajul `AUTH_B`:

```text
[KeyEx: bob] build AuthMsg to ana, new state INIT_RCVD
[Comm] MsgHeader: { AUTH_B from bob to ana sid 191B827A95A09EB7 }
```

Mesajul `AUTH_B` conține tot un câmp:

```text
auth[32]
```

Acesta reprezintă autentificatorul MAC generat de Bob.

După trimiterea mesajului `AUTH_B`, Bob finalizează handshake-ul:

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
[KeyEx: ana] Successful verification of bob's authenticator (MAC-PSK-DHE-VULN)
Successful authentication: remote user is bob
```

Ana finalizează handshake-ul:

```text
[KeyEx: ana] Initiator: Auth handshake done, state ESTABLISHED. Success
```

Această etapă confirmă că autentificarea mutuală reușește într-un scenariu normal: Bob o autentifică pe Ana, iar Ana îl autentifică pe Bob.

---

## Starea finală a sesiunilor

Trace-ul confirmă că ambele sesiuni ajung în starea `ESTABLISHED`:

```text
[Party: ana] 1 sessions
Session[0]: sid 191B827A95A09EB7 from ana to bob state ESTABLISHED

[Party: bob] 1 sessions
Session[0]: sid 191B827A95A09EB7 from bob to ana state ESTABLISHED
```

Acest rezultat arată că protocolul este funcțional în scenariul cu doi participanți onești.

Totuși, o execuție corectă în absența adversarului nu demonstrează securitatea protocolului. Pentru securitate este necesar ca autentificatorul să lege complet identitatea, cheia, sesiunea și transcriptul mesajelor.

---

## Testarea comunicației după handshake

După finalizarea schimbului de chei, sistemul devine pregătit pentru comunicație:

```text
>> System ready for communications <<
```

Ana trimite un mesaj către Bob:

```text
Party[ana]: sends message to bob
[Comm] MsgHeader: { DATA from ana to bob sid 191B827A95A09EB7 }
```

Mesajul este transmis ca `AE_DATA`, deci este protejat prin criptare autentificată.

Bob primește și acceptă mesajul:

```text
Party[bob]: rcvd message from ana (ana). Accepted
```

Apoi Bob transmite un mesaj către Ana:

```text
Party[bob]: sends message to ana
[Comm] MsgHeader: { DATA from bob to ana sid 191B827A95A09EB7 }
```

Ana primește și acceptă mesajul:

```text
Party[ana]: rcvd message from bob (bob). Accepted
```

Această etapă confirmă că, în absența atacului, materialul criptografic derivat este folosit pentru protejarea comunicației în ambele direcții.

---

## De ce protocolul rămâne vulnerabil

Protocolul funcționează corect în acest test, dar este vulnerabil deoarece autentificatorul MAC nu include toate elementele relevante ale sesiunii.

Într-o variantă sigură, autentificatorul trebuie să lege explicit:

* identitatea participantului;
* nonce-urile;
* valorile publice Diffie-Hellman;
* direcția mesajului;
* contextul sesiunii;
* transcriptul complet relevant.

În varianta `MAKE_MAC_DH_M4_ILV`, MAC-ul este valid, dar poate fi folosit într-un context greșit dacă adversarul intercalează mesaje din execuții diferite.

Problema nu este algoritmul MAC în sine. Problema este ce date sunt introduse în MAC.

Dacă MAC-ul nu acoperă complet transcriptul, un adversar poate modifica anumite valori din protocol, în special valorile Diffie-Hellman, fără ca autentificarea să lege corect cheia rezultată de identitatea participantului așteptat.

---

## Concluzie

Trace-ul confirmă execuția funcțională a variantei vulnerabile `MAKE_MAC_DH_M4_ILV` în scenariul cu doi participanți onești.

Rezultatele importante sunt:

* mesajele `INIT_A`, `INIT_B`, `AUTH_A` și `AUTH_B` sunt transmise corect;
* Ana și Bob schimbă nonce-uri și valori publice Diffie-Hellman;
* autentificatorii MAC sunt verificați cu succes;
* ambii participanți ajung în starea `ESTABLISHED`;
* datele transmise după handshake sunt protejate și acceptate.

Totuși, protocolul rămâne vulnerabil la atacuri de tip Interleaving, deoarece autentificatorul MAC nu acoperă complet transcriptul sesiunii. Testul demonstrează că protocolul poate funcționa normal, dar nu demonstrează securitatea lui în prezența unui adversar activ.
