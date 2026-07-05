# Trace — MAKE-SIG-DH-M4-ILV

## Test rulat

```text
TEST_2P_MAKE_SIG_DH_M4_ILV
```

Protocol testat:

```text
MAKE_SIG_DH_M4_ILV
```

Acest test verifică execuția variantei vulnerabile `MAKE_SIG_DH_M4_ILV` între doi participanți onești: `ana` și `bob`.

Important: acest trace nu reprezintă atacul Interleaving propriu-zis. El arată că varianta vulnerabilă poate funcționa corect într-un scenariu normal, fără adversar activ. Vulnerabilitatea apare atunci când un adversar intercalează mesaje din mai multe execuții și profită de faptul că autentificatorul nu acoperă complet transcriptul sesiunii.

---

## Scopul testului

Scopul acestui test este să confirme că protocolul vulnerabil:

* transmite mesajele `INIT_A`, `INIT_B`, `AUTH_A` și `AUTH_B`;
* generează nonce-uri și valori publice Diffie-Hellman;
* verifică semnăturile digitale;
* folosește certificate pentru identificarea participanților;
* ajunge în starea `ESTABLISHED` când nu există adversar activ;
* permite transmiterea de date protejate după finalizarea handshake-ului.

Acest rezultat este important deoarece arată că vulnerabilitatea nu apare dintr-o eroare de implementare evidentă, ci din modul incomplet în care este construit autentificatorul.

---

## Diferență față de varianta sigură SIG-PKC

Varianta sigură `MAKE-IKE-SIG-PKC-DHE 4M` protejează mesajele de autentificare prin criptare autentificată. În trace-ul variantei sigure, mesajele `AUTH_A` și `AUTH_B` conțin câmpul:

```text
edata
```

În schimb, în această variantă vulnerabilă, mesajele `AUTH_A` și `AUTH_B` conțin direct:

```text
auth
cert
```

Acest lucru arată că semnătura și certificatul sunt transmise explicit în mesajul de autentificare, fără aceeași structură protejată prin `edata`.

Mai important, autentificatorul din varianta vulnerabilă nu leagă complet toate elementele sesiunii. Semnătura este validă criptografic, dar nu acoperă întregul transcript necesar pentru prevenirea atacurilor de tip Interleaving.

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
[Comm] MsgHeader: { INIT_A from ana to bob sid 836040A43F29298D }
```

Mesajul `INIT_A` conține:

* nonce-ul Anei;
* valoarea publică Diffie-Hellman a Anei.

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
[Comm] MsgHeader: { INIT_B from bob to ana sid 836040A43F29298D }
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
[Comm] MsgHeader: { AUTH_A from ana to bob sid 836040A43F29298D }
```

În această variantă, mesajul `AUTH_A` conține două câmpuri principale:

```text
auth
cert
```

Câmpul `auth` reprezintă semnătura digitală a Anei, iar câmpul `cert` reprezintă certificatul acesteia.

Această etapă confirmă că autentificarea se bazează pe mecanismul `SIG-PKC`, adică pe semnături digitale și certificate.

---

### 4. Bob verifică autentificarea Anei

Bob primește `AUTH_A` în starea `INIT_RCVD`:

```text
[KeyEx: bob] recvAuth in state INIT_RCVD
```

Verificarea semnăturii reușește:

```text
[KeyEx: bob] Successful verification of ana's authenticator (SIG-PKC-DHE-ILV)
Successful authentication: remote user is ana
```

Această etapă confirmă că:

* semnătura Anei este validă;
* certificatul Anei este acceptat;
* Bob autentifică participantul `ana`;
* protocolul continuă normal în absența unui adversar activ.

Totuși, faptul că semnătura este validă nu înseamnă automat că protocolul este sigur împotriva atacurilor Interleaving. Problema variantei vulnerabile este că semnătura nu acoperă complet transcriptul sesiunii.

---

### 5. Bob construiește mesajul `AUTH_B`

După verificarea Anei, Bob construiește mesajul `AUTH_B`:

```text
[KeyEx: bob] build AuthMsg to ana, new state INIT_RCVD
[Comm] MsgHeader: { AUTH_B from bob to ana sid 836040A43F29298D }
```

Și mesajul `AUTH_B` conține:

```text
auth
cert
```

Câmpul `auth` reprezintă semnătura digitală a lui Bob, iar câmpul `cert` reprezintă certificatul lui Bob.

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
[KeyEx: ana] Successful verification of bob's authenticator (SIG-PKC-DHE-ILV)
Successful authentication: remote user is bob
```

Ana finalizează handshake-ul:

```text
[KeyEx: ana] Initiator: Auth handshake done, state ESTABLISHED. Success
```

Această etapă confirmă că autentificarea mutuală reușește într-un scenariu normal, fără adversar.

---

## Starea finală a sesiunilor

Trace-ul confirmă că ambele sesiuni ajung în starea `ESTABLISHED`:

```text
[Party: ana] 1 sessions
Session[0]: sid 836040A43F29298D from ana to bob state ESTABLISHED

[Party: bob] 1 sessions
Session[0]: sid 836040A43F29298D from bob to ana state ESTABLISHED
```

Acest rezultat arată că protocolul este funcțional în scenariul cu doi participanți onești.

Totuși, faptul că o execuție normală se termină cu succes nu garantează securitatea protocolului. Vulnerabilitatea apare în scenarii cu adversar activ, atunci când acesta poate interfera cu mesajele și poate exploata autentificatorul incomplet.

---

## Testarea comunicației după handshake

După finalizarea schimbului de chei, sistemul devine pregătit pentru comunicație:

```text
>> System ready for communications <<
```

Ana trimite un mesaj către Bob:

```text
Party[ana]: sends message to bob
[Comm] MsgHeader: { DATA from ana to bob sid 836040A43F29298D }
```

Mesajul este transmis ca `AE_DATA`, deci este protejat prin criptare autentificată.

Bob primește și acceptă mesajul:

```text
Party[bob]: rcvd message from ana (ana). Accepted
```

Apoi Bob transmite un mesaj către Ana:

```text
Party[bob]: sends message to ana
[Comm] MsgHeader: { DATA from bob to ana sid 836040A43F29298D }
```

Ana primește și acceptă mesajul:

```text
Party[ana]: rcvd message from bob (bob). Accepted
```

Această etapă confirmă că, în absența atacului, materialul criptografic derivat poate fi folosit pentru protejarea comunicației în ambele direcții.

---

## De ce protocolul rămâne vulnerabil

Protocolul funcționează corect în acest test, dar este vulnerabil deoarece autentificatorul nu include toate elementele relevante ale sesiunii.

Într-o variantă sigură, autentificatorul trebuie să lege explicit:

* identitatea participantului;
* nonce-urile;
* valorile publice Diffie-Hellman;
* direcția mesajului;
* contextul sesiunii;
* transcriptul complet relevant.

În varianta `MAKE_SIG_DH_M4_ILV`, semnătura este validă, dar poate fi folosită într-un context greșit dacă adversarul intercalează mesaje din execuții diferite.

Prin urmare, problema nu este semnătura digitală în sine. Problema este ce anume se semnează.

---

## Concluzie

Trace-ul confirmă execuția funcțională a variantei vulnerabile `MAKE_SIG_DH_M4_ILV` în scenariul cu doi participanți onești.

Rezultatele importante sunt:

* mesajele `INIT_A`, `INIT_B`, `AUTH_A` și `AUTH_B` sunt transmise corect;
* Ana și Bob schimbă nonce-uri și valori publice Diffie-Hellman;
* semnăturile digitale sunt verificate cu succes;
* certificatele participanților sunt acceptate;
* ambii participanți ajung în starea `ESTABLISHED`;
* datele transmise după handshake sunt protejate și acceptate.

Totuși, protocolul rămâne vulnerabil la atacuri de tip Interleaving, deoarece autentificatorul nu acoperă complet transcriptul sesiunii. Testul demonstrează că protocolul poate funcționa normal, dar nu demonstrează securitatea lui în prezența unui adversar activ.
